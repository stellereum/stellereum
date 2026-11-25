use crate::sharding::{ShardId, Transaction};

pub const BUCKET_STELLEREUM_BLOCKS: &str = "stell_blocks";
pub const BUCKET_STELLEREUM_STATE: &str = "stell_state";
/// Replicated bucket holding each shard's published head pointer.
pub const BUCKET_STELLEREUM_HEAD: &str = "stell_head";
/// Replicated bucket holding published block HEADERS, so a cold node can chain from
/// a state snapshot up to the head using headers only (small, published every block)
/// rather than bodies (large, kept for a bounded window).
pub const BUCKET_STELLEREUM_HEADERS: &str = "stell_headers";

/// Chain epoch: a short tag derived from the genesis fingerprint, mixed into every
/// blob name this node publishes or reads.
///
/// Without it, a data wipe does NOT wipe the network: the DHT still holds the old
/// chain's head pointer, headers and snapshots under the same well-known names, and a
/// freshly-started node honestly tries to follow a chain that no longer exists. That
/// was observed live -- after wiping both data directories, a new node started at
/// height 1 and then went looking for the previous run's height-488 head, because the
/// blobs survived in the overlay.
///
/// Namespacing by epoch makes a wiped node unable to see the old chain at all, so
/// "start fresh" actually means fresh. Two networks with different genesis parameters
/// also cannot contaminate each other, which is the same property that makes a public
/// testnet safe to run beside a private one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTag(String);

impl EpochTag {
    /// Build a tag from a genesis fingerprint. Short, hex, filesystem- and
    /// blob-name-safe.
    pub fn from_genesis(fingerprint: &[u8; 32]) -> Self {
        Self(hex::encode(&fingerprint[..8]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for EpochTag {
    /// Before a genesis fingerprint exists (early startup, unit tests) fall back to a
    /// fixed tag rather than an empty string, so names stay well-formed.
    fn default() -> Self {
        Self("genesis".to_string())
    }
}

pub(super) fn header_name(epoch: &EpochTag, height: u64) -> String {
    format!("{}_h_{height}", epoch.as_str())
}

/// Content/shard-scoped blob name for [`crate::storage::BlockHeaderRecordV2`].
pub fn header_v2_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_h2_{shard_id}_{height}", epoch.as_str())
}

/// Content-addressed DHT name for a `SnapV4` manifest (`SNAP-DHT-NAME`):
/// binds `(epoch, shard_id, height, state_root)` so poisoning one state root
/// at `height` cannot block or alias an honest manifest at the same height.
pub fn snapv4_manifest_name(
    epoch: &EpochTag,
    shard_id: u32,
    height: u64,
    state_root: &[u8; 32],
) -> String {
    format!(
        "{}_snapm_{shard_id}_{height}_{}",
        epoch.as_str(),
        hex::encode(&state_root[..8])
    )
}

/// Content-addressed DHT name for a `SnapV4` unit/chunk (`chunk_hash`).
pub fn snapv4_unit_name(epoch: &EpochTag, shard_id: u32, chunk_hash: &[u8; 32]) -> String {
    format!(
        "{}_snapu_{shard_id}_{}",
        epoch.as_str(),
        hex::encode(chunk_hash)
    )
}

pub(super) fn header_index_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_hi_{shard_id}_{height}", epoch.as_str())
}

/// Well-known blob name for a height's precommit-QC sidecar (A1 anchor).
/// SHARD-SCOPED (unlike `header_name`): a cross-shard QC splice at the same
/// height must be impossible by construction — binding checks cover height
/// and hash, never shard.
pub(super) fn header_qc_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_hq_{shard_id}_{height}", epoch.as_str())
}

/// Well-known blob name for a shard's head pointer, scoped to a chain epoch.
pub(super) fn head_name(epoch: &EpochTag, shard_id: u32) -> String {
    format!("{}_shard_{shard_id}_head", epoch.as_str())
}

/// Block bodies and state snapshots are content-addressed by hash/height, but they are
/// still scoped so a wiped node does not read a previous chain's state.
pub(super) fn block_name(epoch: &EpochTag, hash_hex: &str) -> String {
    format!("{}_blk_{hash_hex}", epoch.as_str())
}

pub(super) fn snapshot_name(epoch: &EpochTag, shard_id: u32, height: u64) -> String {
    format!("{}_snap_{shard_id}_{height}", epoch.as_str())
}

/// Well-known blob name for the "latest state snapshot" pointer: the exact
/// height of the most recently published state snapshot. Snapshots land on
/// arbitrary heights (capture completes when the worker finishes, not on
/// %100), so probing round hundreds systematically misses them. The pointer
/// (a few bytes, FOREVER TTL like the snapshots) lets a catcher read one
/// tiny blob and fetch the exact boundary first.
pub(super) fn snapshot_latest_name(epoch: &EpochTag, shard_id: u32) -> String {
    format!("{}_snap_latest_{shard_id}", epoch.as_str())
}

pub const PREFIX_LATEST_HEIGHT: &str = "stell:height:";
pub const PREFIX_BLOCK_HASH: &str = "stell:block:";
pub const PREFIX_MEMPOOL_TX: &str = "stell:mempool:";
pub const PREFIX_SHARD_MEMPOOL: &str = "stell:shard_mempool:";
pub const PREFIX_CROSS_SHARD: &str = "stell:cross_shard:";
pub const PREFIX_ORACLE: &str = "stell:oracle:";
pub const PREFIX_MEV_COMMIT: &str = "stell:mev:commit:";

/// One entry of the DHT mempool store: a plain transaction or a SEALED
/// envelope (the epoch-seal path — the ciphertext only).
#[derive(Clone, Debug)]
pub enum MempoolEntry {
    Plain(Transaction),
    Sealed(crate::mev_epoch::SealedEnvelope),
}

/// Base name of the P2P gossip topic that carries cross-shard messages.
pub const CROSS_SHARD_TOPIC_BASE: &str = "stell/cross_shard";

/// The gossip topic carrying the cross-shard messages addressed to
/// `target_shard`.
///
/// EPOCH-SCOPED (not optional): a pubsub topic is a GLOBAL name in the
/// overlay — every node subscribed to it receives what is published under it,
/// and the message is relayed across the mesh. A fixed topic name would let a
/// node of one chain receive another chain's cross-shard messages and try to
/// credit them: the same namespace leak that epoch-scoped consensus topics
/// already fixed (see [`crate::consensus_net::consensus_topic`]).
///
/// SHARD-SCOPED as well: the topic is a per-shard mailbox, not a global
/// firehose that every shard then filters. A shard must only ever hear the
/// messages addressed to IT, so the routing is by construction rather than by
/// a filter a future bug could skip.
pub fn cross_shard_topic(target_shard: ShardId, epoch: &str) -> String {
    format!("{CROSS_SHARD_TOPIC_BASE}/{epoch}/{target_shard}")
}

/// The blob name a block body is stored under.
///
/// This MUST stay byte-identical to the name `fetch_block` looks up, or a body is
/// published into a bucket slot nobody will ever ask for and the peer stays stuck on
/// `block sync: missing block`. Exposed as a function so a test can pin the
/// convention instead of trusting a comment to keep it.
///
/// Takes the epoch, because bisecting the name and the reader is exactly the failure
/// this exists to prevent: `broadcast_block` wrote under an epoch-scoped name while
/// the retro-publish path wrote the bare hash, so the two produced different slots for
/// the same block and neither could find the other's body.
pub fn block_body_blob_name(epoch: &EpochTag, block_hash: &[u8; 32]) -> String {
    block_name(epoch, &hex::encode(block_hash))
}
