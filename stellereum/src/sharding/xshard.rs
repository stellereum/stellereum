use super::block::{ShardHeaderCommitment, XSHARD_FULL_COMMITMENT_TAG};
use super::envelope::global_implicit_key_registry;
use super::topology::{ShardId, MASTERCHAIN_SHARD};
use super::transaction::Transaction;
use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// Cross-shard atomic transfer message with tight-coupling cryptographic proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardMessage {
    pub msg_id: [u8; 32],
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub tx: Transaction,
    pub merkle_inclusion_proof: Option<MerkleProof>,
    pub source_state_root: CellHash,
    pub finalized_in_block: [u8; 32],
    /// Sender's balance proven at `source_state_root` (binds the transfer to the
    /// account leaf and lets the target check the sender actually had the funds).
    #[serde(default)]
    pub source_balance: u64,
    pub bounce: bool,
    pub bounced: bool,
    /// Marks a message as already consensus-attested (locally generated only).
    /// SECURITY: MUST NEVER be set from untrusted network input. If true,
    /// `verify_inclusion` is bypassed. This flag exists for in-process routing
    /// (simulator / same-validator pipeline), not for wire messages.
    pub trusted: bool,
    #[serde(default)]
    pub sender_pubkey_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub sender_scheme: Option<u8>,
    /// The §9 TWO-PHASE-COMMIT phase of this record.
    ///
    /// `0` (`XPC_LEGACY`) means "this is a pre-2PC record": its kind is
    /// derived from the direction and the legacy `bounce` / `bounced` flags,
    /// exactly as before. A non-zero value names a 2PC phase (PREPARE,
    /// PREPARE-ACK, COMMIT, ABORT-REQUEST, ABORT-ACK) and the phase ALONE
    /// decides the kind — the direction must match the phase, or the record
    /// is `Unknown` and is refused.
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one of the struct, so a
    /// message persisted before the 2PC existed simply ends its byte stream
    /// one field early. `serde(default)` covers the self-describing formats
    /// and the bincode path is covered by [`de_xpc_phase`], which reads a
    /// missing trailing field as "this message predates the 2PC" (the legacy
    /// phase) instead of failing the whole decode. The legacy path is
    /// byte-identical: a legacy message's phase is 0 and its `msg_id` is
    /// computed exactly as before.
    #[serde(default, deserialize_with = "de_xpc_phase")]
    pub xpc_phase: u8,
}

/// Domain tag of the SOURCE-side ESCROW/DEBIT record of a legacy cross-shard
/// value transfer (XSHARD-01).
///
/// The record lives in the source shard's state trie, keyed by
/// [`xshard_escrow_state_key`], with the value built by
/// [`xshard_escrow_state_value`]. It is written by the source's block-apply
/// path and ONLY for an outbound transfer whose escrow transaction applied, so
/// its existence proves that the source DEBITED the sender for this transfer —
/// which is exactly what the inbound credit needs, and what the sender's
/// account leaf (an affordability statement about the PRE-transfer state) does
/// not prove.
pub const XSHARD_ESCROW_TAG: &[u8] = b"STELLEREUM_XSHARD_ESCROW_V1";

/// Key-domain tag of the escrow record (kept distinct from the value tag so the
/// key cannot be used as a value preimage or vice versa).
const XSHARD_ESCROW_KEY_TAG: &[u8] = b"STELLEREUM_XSHARD_ESCROW_KEY_V1";

/// State-trie key of the escrow/debit record of one cross-shard transfer.
///
/// Keyed by the transfer's transaction hash (which itself commits the shards,
/// sender, recipient, amount, gas and nonce), so two transfers can never share
/// an escrow record.
pub fn xshard_escrow_state_key(tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(XSHARD_ESCROW_KEY_TAG);
    hasher.update(tx_hash);
    hasher.finalize().into()
}

/// State-trie value of the escrow/debit record of one cross-shard transfer.
///
/// Commits the WHOLE transfer (shard pair, sender, recipient, amount) so the
/// record a target verifies is bound to exactly one transfer and cannot be
/// re-used for a different recipient or amount. Deterministic: a pure function
/// of the transaction, so every node that applied the same block writes the
/// same leaf and derives the same state root.
pub fn xshard_escrow_state_value(tx: &Transaction) -> Vec<u8> {
    let mut value = Vec::with_capacity(XSHARD_ESCROW_TAG.len() + 4 + 4 + 32 + 32 + 32 + 8);
    value.extend_from_slice(XSHARD_ESCROW_TAG);
    value.extend_from_slice(&tx.source_shard.to_be_bytes());
    value.extend_from_slice(&tx.target_shard.to_be_bytes());
    value.extend_from_slice(&tx.from);
    value.extend_from_slice(&tx.to);
    value.extend_from_slice(&tx.amount.to_be_bytes());
    value
}

impl CrossShardMessage {
    /// Construct a wire (untrusted) cross-shard message. Requires a Merkle proof
    /// for value-bearing transfers — a missing proof will be rejected.
    pub fn new(
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
        proof: Option<MerkleProof>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(source_shard.to_be_bytes());
        hasher.update(target_shard.to_be_bytes());
        hasher.update(tx.compute_tx_hash());
        hasher.update(finalized_in_block);
        let msg_id = hasher.finalize().into();

        let mut sender_pubkey_hash = None;
        let mut sender_scheme = None;

        if let Some(env) = tx.pq_envelope() {
            if let Some(ref pk) = env.pubkey {
                sender_scheme = Some(env.scheme.id());
                sender_pubkey_hash = Some(*blake3::hash(pk).as_bytes());
            } else if let Some((_, pk)) = global_implicit_key_registry().lookup(&tx.from) {
                sender_scheme = Some(env.scheme.id());
                sender_pubkey_hash = Some(*blake3::hash(&pk).as_bytes());
            }
        } else if let Some((scheme, pk)) = global_implicit_key_registry().lookup(&tx.from) {
            sender_scheme = Some(scheme.id());
            sender_pubkey_hash = Some(*blake3::hash(&pk).as_bytes());
        }

        Self {
            msg_id,
            source_shard,
            target_shard,
            tx,
            merkle_inclusion_proof: proof,
            source_state_root,
            finalized_in_block,
            source_balance: 0,
            bounce: true,
            bounced: false,
            trusted: false,
            sender_pubkey_hash,
            sender_scheme,
            xpc_phase: crate::xshard2pc::XPC_LEGACY,
        }
    }

    /// Attach the source-account balance that the inclusion proof attests to.
    pub fn with_source_balance(mut self, balance: u64) -> Self {
        self.source_balance = balance;
        self
    }

    /// Attach the sender's post-quantum scheme and public key hash (SEC-PQ-03).
    pub fn with_sender_pubkey_hash(mut self, scheme: u8, pubkey_hash: [u8; 32]) -> Self {
        self.sender_scheme = Some(scheme);
        self.sender_pubkey_hash = Some(pubkey_hash);
        self
    }

    /// Clear PQ leaf metadata when the sender's account at `source_state_root`
    /// is unpinned (`pubkey_hash == None`, 16-byte leaf) so inclusion
    /// verification checks the 16-byte leaf actually committed in that trie.
    pub fn with_unpinned_sender(mut self) -> Self {
        self.sender_scheme = None;
        self.sender_pubkey_hash = None;
        self
    }

    /// Construct a locally-trusted message (already attested by this node's own
    /// consensus pipeline). NEVER deserialize a network message into this state.
    pub fn new_trusted(
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
    ) -> Self {
        let mut m = Self::new(
            source_shard,
            target_shard,
            tx,
            source_state_root,
            finalized_in_block,
            None,
        );
        m.trusted = true;
        m
    }

    /// Verify cryptographic tight coupling Merkle proof against source state root.
    /// SECURITY (Nomad-style forgery prevention): a missing proof is REJECTED
    /// unless the message is explicitly locally-trusted.
    pub fn verify_inclusion(&self) -> bool {
        if self.trusted {
            return true;
        }
        self.verify_inclusion_untrusted()
    }

    /// The same inclusion check but the local `trusted` shortcut is IGNORED.
    ///
    /// M2: this is the ONLY form a target shard may use when applying a message
    /// that travelled inside a block. `trusted` is set by the local producer of
    /// a message, but the flag is serialized with the block and a Byzantine
    /// proposer could set it on a message with no proof at all; honoring it here
    /// would mint value out of nothing on every node that applied the block.
    /// Requiring the Merkle proof makes the mint prove it corresponds to a
    /// source-shard account leaf.
    pub fn verify_inclusion_strict(&self) -> bool {
        self.verify_inclusion_untrusted()
    }

    /// Verify the SOURCE-SIDE ESCROW/DEBIT proof of a legacy value transfer
    /// (XSHARD-01).
    ///
    /// WHAT THIS PROVES, AND WHY IT IS NOT THE SAME AS [`Self::verify_inclusion_strict`].
    /// `verify_inclusion_strict` proves the SENDER'S ACCOUNT LEAF
    /// (`balance || nonce`) at `source_state_root`. That is a statement about
    /// the source's state BEFORE the transfer: "the sender could afford the
    /// amount". It says nothing about the transfer being included in any
    /// source block, and nothing about the amount having been removed from
    /// the sender. A colluding target proposer can therefore pair a funded
    /// sender account with a signed-but-never-applied transaction and a
    /// perfectly valid affordability proof, and mint the amount on the
    /// target: the sender's source balance is untouched, so the "same" coins
    /// are credited twice (once as the unchanged source balance, once as the
    /// target credit). This proof closes that hole.
    ///
    /// The leaf proven here is the SOURCE's escrow/debit record for the
    /// transfer, written by the source shard's block-APPLY path
    /// (`InMemoryStateEngine::record_legacy_escrow_receipts`) ONLY for an
    /// outbound legacy transfer whose escrow transaction actually applied
    /// (`status == true`). The record is keyed by the transfer's transaction
    /// hash and commits the full transfer (source/target shard, sender,
    /// recipient, amount), so it cannot be replayed for a different transfer.
    /// A source that never debited the sender has no such leaf, and a
    /// Byzantine target cannot fabricate one: the Merkle proof must verify
    /// against a `source_state_root` that the target anchors to a locally
    /// finalized source header ([`Self::verify_escrow_anchored`]).
    ///
    /// The local `trusted` shortcut is IGNORED for the same reason
    /// [`Self::verify_inclusion_strict`] ignores it: `trusted` travels with
    /// attacker-supplied block content.
    pub fn verify_escrow_proof(&self) -> bool {
        // Untrusted-boundary id recompute first (same rule as every other
        // proof verifier here): a rebound message id is refused before any
        // trie work.
        if !self.verify_msg_id() {
            return false;
        }
        // The escrow leaf commits the transfer's OWN shard pair, so the
        // message must not claim a direction the leaf does not describe.
        if self.source_shard != self.tx.source_shard || self.target_shard != self.tx.target_shard {
            return false;
        }
        let Some(proof) = &self.merkle_inclusion_proof else {
            return false;
        };
        let tx_hash = self.tx.compute_tx_hash();
        let key = xshard_escrow_state_key(&tx_hash);
        let value = xshard_escrow_state_value(&self.tx);
        PatriciaTrie::verify_merkle_proof(&self.source_state_root, &key, &value, proof)
    }

    /// Anchored escrow proof: [`Self::verify_escrow_proof`] checked against a
    /// state root that a LOCALLY FINALIZED source header committed to — the
    /// C1 anchor rule of [`Self::verify_anchored`], applied to the escrow leaf
    /// instead of the account leaf.
    ///
    /// `false` covers both "forged" and "not finalized here yet"; callers must
    /// treat it as NOT-READY (never credit, never claim the replay key), so a
    /// lagging node retries after catching up. A missing/poisoned registry
    /// fails closed.
    pub fn verify_escrow_anchored(&self, registry: Option<&FinalizedHeaderRegistry>) -> bool {
        let Some(reg) = registry else {
            return false;
        };
        if !reg.anchor_holds(
            self.source_shard,
            &self.finalized_in_block,
            &self.source_state_root,
        ) {
            return false;
        }
        self.verify_escrow_proof()
    }

    /// Anchored inclusion (C1 fix): the Merkle proof PLUS a check that
    /// `source_state_root` is the state root of a source block THIS process
    /// finalized (or adopted with a verified QC) — looked up by the
    /// `finalized_in_block` hash the message commits to. A self-attested
    /// root (attacker trie + valid-for-that-root proof) fails here because
    /// its hash names no committed header. A lagging node fails here too
    /// (miss, not proof-failure): callers must treat that as NOT-READY
    /// (skip embedding / refuse the carrying block and retry after catching
    /// up), never as verified. `None` registry (single-shard contexts,
    /// unit tests) also fails closed.
    ///
    /// NOTE: this is the AFFORDABILITY check (sender account leaf). It is the
    /// correct rule for the OPENING §9 PREPARE (which does not move value),
    /// but it is NOT sufficient to pay an inbound legacy credit: see
    /// [`Self::verify_escrow_proof`] / [`Self::verify_escrow_anchored`]
    /// (XSHARD-01).
    pub fn verify_anchored(&self, registry: Option<&FinalizedHeaderRegistry>) -> bool {
        let Some(reg) = registry else {
            return false;
        };
        if !reg.anchor_holds(
            self.source_shard,
            &self.finalized_in_block,
            &self.source_state_root,
        ) {
            return false;
        }
        self.verify_inclusion_untrusted()
    }

    fn verify_inclusion_untrusted(&self) -> bool {
        // XSHARD INTEGRITY (untrusted boundary): the carried `msg_id` is
        // recomputed from the message body (domain-aware, see
        // `expected_msg_id`) and a mismatch refuses the message. The id is
        // assigned at construction and never recomputed on decode/apply, so
        // without this a Byzantine carrier could rebind a valid proof to a
        // different (source, target, tx, block) tuple.
        if !self.verify_msg_id() {
            return false;
        }
        let Some(proof) = &self.merkle_inclusion_proof else {
            // No proof from an untrusted source -> reject.
            return false;
        };
        // The proven balance must actually cover the transfer, so an attacker
        // cannot inflate `amount` and keep an old proof for a smaller balance.
        if self.source_balance < self.tx.amount {
            return false;
        }
        // Prove the SENDER ACCOUNT LEAF (balance || nonce) at the source state
        // root — the same 16-byte encoding the state trie uses. This binds the
        // message to real state (not an ad-hoc amount||nonce value).
        let mut account_value = Vec::with_capacity(16);
        account_value.extend_from_slice(&self.source_balance.to_be_bytes());
        account_value.extend_from_slice(&self.tx.nonce.to_be_bytes());

        // Support pinned PQ accounts with explicit proof metadata (SEC-PQ-03)
        // If sender_pubkey_hash and sender_scheme are present, construct the exact 49-byte leaf:
        // account_value (16B) || scheme (1B) || pubkey_hash (32B)
        // and verify the Merkle proof against source_state_root!
        // This ensures Shard 2 can verify the proof completely independently without needing local RAM keys!
        if let (Some(pk_hash), Some(scheme)) = (self.sender_pubkey_hash, self.sender_scheme) {
            let mut pq_leaf = Vec::with_capacity(49);
            pq_leaf.extend_from_slice(&account_value);
            pq_leaf.push(scheme);
            pq_leaf.extend_from_slice(&pk_hash);
            return PatriciaTrie::verify_merkle_proof(
                &self.source_state_root,
                &self.tx.from,
                &pq_leaf,
                proof,
            );
        }

        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &account_value,
            proof,
        ) {
            return true;
        }

        // Support pinned PQ accounts (49-byte leaf: balance || nonce || scheme || pk_hash)
        if let Some(env) = self.tx.pq_envelope() {
            let maybe_pk = env.pubkey.as_ref().cloned().or_else(|| {
                global_implicit_key_registry()
                    .lookup(&self.tx.from)
                    .map(|(_, pk)| pk)
            });
            if let Some(ref pk) = maybe_pk {
                let pk_hash = blake3::hash(pk);
                let mut pq_leaf = Vec::with_capacity(49);
                pq_leaf.extend_from_slice(&account_value);
                pq_leaf.push(env.scheme.id());
                pq_leaf.extend_from_slice(pk_hash.as_bytes());
                if PatriciaTrie::verify_merkle_proof(
                    &self.source_state_root,
                    &self.tx.from,
                    &pq_leaf,
                    proof,
                ) {
                    return true;
                }
            }
        }

        // Support pinned accounts registered in implicit key registry (even if tx is not marked PQ)
        if let Some((scheme, pk)) = global_implicit_key_registry().lookup(&self.tx.from) {
            let pk_hash = blake3::hash(&pk);
            let mut pq_leaf = Vec::with_capacity(49);
            pq_leaf.extend_from_slice(&account_value);
            pq_leaf.push(scheme.id());
            pq_leaf.extend_from_slice(pk_hash.as_bytes());
            if PatriciaTrie::verify_merkle_proof(
                &self.source_state_root,
                &self.tx.from,
                &pq_leaf,
                proof,
            ) {
                return true;
            }
        }

        // FULL-PQ: the legacy pinned-Ed25519 branches were DELETED. They
        // accepted a 49-byte leaf carrying scheme id 0x01 with
        // `pubkey_hash = blake3(from)` or `pubkey_hash = from`, i.e. a
        // classical account shape that no longer exists (scheme 0x01 is
        // refused by `PqScheme::from_id`). A proof for such a leaf is now
        // simply not verifiable — the message fails closed here.

        false
    }

    /// True when this message is an OUTBOUND (produce) record for `shard_id`:
    /// the value leaves this shard when the block that carries it is applied.
    pub fn is_outbound_for(&self, shard_id: ShardId) -> bool {
        self.source_shard == shard_id && self.target_shard != shard_id
    }

    /// True when this message is an INBOUND (consume) record for `shard_id`:
    /// the recipient is credited on this shard when the block is applied.
    pub fn is_inbound_for(&self, shard_id: ShardId) -> bool {
        self.target_shard == shard_id && self.source_shard != shard_id
    }
}

/// Replay-protection key for a consumed cross-shard message.
///
/// `Block`/`Transaction`/`CrossShardMessage` gain NO new fields (bincode 1.3
/// would break every persisted block), so the source height is not carried as a
/// separate integer. The source block identity is [`CrossShardMessage::finalized_in_block`]
/// (the source shard's finalized head that the producing block extends) and the
/// `msg_id` commits to the source shard, the target shard, the full transaction
/// hash and that block identity. `(source_shard, finalized_in_block, msg_id)` is
/// therefore a unique, deterministic key for the source (height, shard, id):
/// two blocks at different source heights cannot share it, and it is identical
/// on every node that saw the same source block.
///
/// The carried `msg_id` is recomputed at every untrusted boundary
/// ([`CrossShardMessage::verify_msg_id`]): a key built from a rebound id never
/// matches the honest key, so a forged carrier cannot alias or shadow a real
/// lifecycle in the consumed/produced/completed sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CrossShardKey {
    pub source_shard: ShardId,
    pub finalized_in_block: [u8; 32],
    pub msg_id: [u8; 32],
}
/// Snapshot schema version of the durable finalized-header registry blob.
///
/// Bump ONLY with a decoder that still accepts the previous version: a node
/// that cannot decode its own blob starts with an EMPTY registry (fail closed,
/// see [`FinalizedHeaderRegistry::restore_from_bytes`]), and every cross-shard
/// message produced before that restart becomes unverifiable until re-anchored.
const REGISTRY_SNAPSHOT_VERSION: u32 = 1;

/// How many non-genesis `(shard, block_hash) -> root` anchors are retained PER
/// SHARD, both in memory and in the persisted blob.
///
/// The anchor map would otherwise grow forever (one entry per finalized block
/// per shard). A cross-shard message names the source head its producing block
/// extends and is consumed within a couple of heights in the honest flow, so a
/// few hundred heights of history is ample; a target that lags further re-syncs
/// and re-adopts the source blocks (which re-anchors them). The bound is a
/// pure function of the retained heights, so two nodes at the same finalized
/// height retain the same window (see [`FinalizedHeaderRegistry::prune_anchors`]).
pub const REGISTRY_ANCHOR_WINDOW: usize = 512;

/// How many height-0 (genesis) anchors are retained per shard. Genesis anchors
/// are exempt from the height window because the first cross-shard messages of
/// every chain name the genesis parent and no later finalize event re-records
/// it. In normal operation there is exactly one per shard; the cap only keeps a
/// locally misbehaving caller from growing the snapshot without bound.
pub const REGISTRY_GENESIS_ANCHORS_PER_SHARD: usize = 16;

/// Hard upper bounds applied to a decoded blob (a corrupt or hostile-length
/// blob must fail closed, not allocate without limit).
const REGISTRY_MAX_ANCHORS: usize = 1_000_000;
const REGISTRY_MAX_SHARDS: usize = 4096;
/// Maximum accepted encoded registry blob (bincode limit).
const REGISTRY_BLOB_LIMIT: u64 = 8 * 1024 * 1024;

/// Durable sink for registry snapshots.
///
/// Implemented by the node's [`crate::storage::AsyncPersistence`] so the
/// finalize path only ENQUEUES a bounded `Vec<u8>` and never touches disk.
/// The trait lives here (not a direct storage dependency) so the sharding layer
/// does not depend on the storage implementation.
pub trait FinalizedHeaderSink: Send + Sync {
    /// Persist one complete, self-contained registry snapshot. Later calls
    /// replace earlier ones: the registry blob is latest-state, not a journal.
    fn persist_finalized_headers(&self, bytes: Vec<u8>);
}

/// `(shard, block hash)` key of one anchor.
type AnchorKey = (ShardId, [u8; 32]);

/// One anchor entry: the root the message is checked against plus the height
/// of the block it belongs to (height 0 = genesis / caller without a height).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AnchorEntry {
    root: crate::cell::CellHash,
    height: u64,
}

/// Wire/serialized form of a registry (or of a delta between two registries).
///
/// `anchors` are sorted by `(shard, block_hash)` and `latest` by `shard`, so
/// the bincode bytes are deterministic: two nodes holding the same anchors and
/// heads serialize byte-identically regardless of insertion order.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FinalizedHeaderDelta {
    pub anchors: Vec<(ShardId, [u8; 32], u64, crate::cell::CellHash)>,
    pub latest: Vec<ShardHeaderCommitment>,
}

/// Bincode envelope. Self-describing version first, then a SHA-256 checksum of
/// the version+payload and the encoded payload itself.
///
/// The checksum is what makes corruption FAIL CLOSED: a bit flip in any anchor
/// root would otherwise still decode as a perfectly-shaped (but forged-looking)
/// registry. The decode path refuses a mismatch, and hydration then clears the
/// registry instead of trusting it.
#[derive(Serialize, Deserialize)]
struct RegistrySnapshotV1 {
    version: u32,
    checksum: [u8; 32],
    payload: Vec<u8>,
}

/// Inner payload of [`RegistrySnapshotV1`].
#[derive(Serialize, Deserialize)]
struct RegistryPayloadV1 {
    anchors: Vec<(ShardId, [u8; 32], u64, crate::cell::CellHash)>,
    latest: Vec<ShardHeaderCommitment>,
}

/// Domain tag mixed into the registry snapshot checksum.
const REGISTRY_SNAPSHOT_TAG: &[u8] = b"STELLEREUM_XSHARD_HEADERS_V1";

/// Process-local registry of finalized block headers, shared by every shard
/// runtime in the process (C1 anchor). Maps (shard, source block hash) to the
/// state root THIS process committed to — keyed by PAIR because different
/// shards' geneses (and the zero-hash genesis placeholder below) must never
/// collide. Reads never block consensus: lookups are a BTreeMap probe, and
/// a MISS is fail-closed (message not verifiable YET — the proposer skips
/// it, a validator refuses the block carrying it; both retry after catching
/// up). Wrote on finalize AND adopt (adopted blocks carry verified QCs, so
/// they anchor exactly like local finals) plus an explicit genesis note at
/// every chain start (the first messages reference the genesis parent, which
/// no finalize event ever records). NEVER populated from gossip, RPC, or DHT
/// blobs: only block-application paths write here, so an attacker cannot
/// plant a root.
///
/// DURABILITY: the registry is snapshotted to its own `xshard_headers` sled
/// tree through an [`FinalizedHeaderSink`] (the same `AsyncPersistence` queue
/// every other domain uses) after each mutation, and is hydrated again at
/// startup. Without this, every anchor died with the process and a restart
/// made all older cross-shard messages unverifiable. The blob carries only the
/// latest heads plus the bounded anchor window above; restoring it can ADD
/// anchors but never accepts a root from the network — the bytes come solely
/// from this node's own disk, written by block-application paths.
#[derive(Clone, Default)]
pub struct FinalizedHeaderRegistry {
    headers: BTreeMap<AnchorKey, AnchorEntry>,
    /// The latest finalized header of every shard this process finalized
    /// (TON `shard_hashes` model): what a masterchain block publishes.
    /// Written ONLY by the block-application paths (finalize / adopt), never
    /// from gossip, RPC or DHT blobs, so an attacker cannot plant a head.
    latest: BTreeMap<ShardId, ShardHeaderCommitment>,
    /// Durable sinks. Never serialized (a sink is runtime plumbing, not
    /// registry state) and never populated from decoded bytes.
    sinks: Vec<Arc<dyn FinalizedHeaderSink>>,
}

impl std::fmt::Debug for FinalizedHeaderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizedHeaderRegistry")
            .field("anchors", &self.headers.len())
            .field("latest", &self.latest)
            .field("sinks", &self.sinks.len())
            .finish()
    }
}

impl FinalizedHeaderRegistry {
    /// Record a finalized block. Idempotent (same hash = same header).
    ///
    /// A caller that knows the block height (the finalize/adopt paths do)
    /// should use [`Self::note_finalized_anchor_at`]; this height-less form
    /// records the anchor as a genesis-height entry, which the window prune
    /// always retains.
    pub fn note_finalized(
        &mut self,
        shard: ShardId,
        block_hash: [u8; 32],
        state_root: crate::cell::CellHash,
    ) {
        self.upsert_anchor((shard, block_hash), state_root, 0);
        self.prune_anchors();
        self.persist();
    }

    /// Record the ANCHOR root of a finalized block: the state root the shard
    /// reached AFTER applying that block.
    ///
    /// WHY THIS IS NOT THE BLOCK'S DECLARED ROOT. A block declares the state
    /// root of its PARENT (the root it was built on - the pre-state
    /// convention this codebase uses), so the root a cross-shard message
    /// carries (the state its inclusion proof was made against) is the
    /// POST-APPLY root of the block the message names, not that block's
    /// declared root. Anchoring the message against the DECLARED root made
    /// every cross-shard transfer produced after a state-changing block
    /// un-anchorable: the target could never verify it, so the transfer was
    /// silently never consumed. The anchor map therefore holds the
    /// post-apply root, and the published shard head keeps the declared root
    /// (that is the root the block itself commits to).
    ///
    /// `note_finalized_commitment` writes the DECLARED root into the anchor
    /// map for backward compatibility; this method overwrites it with the
    /// post-apply root, and the runtime calls it right after.
    pub fn note_finalized_anchor(
        &mut self,
        shard: ShardId,
        block_hash: [u8; 32],
        post_apply_root: crate::cell::CellHash,
    ) {
        // No height available at this legacy entry point: record it as a
        // genesis-height anchor, which is never evicted by the height window.
        self.note_finalized_anchor_at(shard, 0, block_hash, post_apply_root);
    }

    /// [`Self::note_finalized_anchor`] WITH the block height, so the bounded
    /// window can prune by height deterministically instead of by insertion
    /// order (which differs between a live node and a syncing one).
    pub fn note_finalized_anchor_at(
        &mut self,
        shard: ShardId,
        height: u64,
        block_hash: [u8; 32],
        post_apply_root: crate::cell::CellHash,
    ) {
        self.upsert_anchor((shard, block_hash), post_apply_root, height);
        self.prune_anchors();
        self.persist();
    }

    /// Insert/update one anchor. The root follows the caller (the runtime
    /// overwrites the declared root with the post-apply root), while the height
    /// only ever moves FORWARD: a height-less legacy note must never downgrade
    /// a real finalize height and thereby change which window is pruned.
    fn upsert_anchor(&mut self, key: AnchorKey, root: crate::cell::CellHash, height: u64) {
        let entry = self
            .headers
            .entry(key)
            .or_insert(AnchorEntry { root, height });
        entry.root = root;
        if height > entry.height {
            entry.height = height;
        }
    }

    /// Look up a source block hash. Returns the state root this process
    /// committed to — `None` means "not finalized here (yet)".
    pub fn lookup(&self, shard: ShardId, block_hash: &[u8; 32]) -> Option<crate::cell::CellHash> {
        self.headers.get(&(shard, *block_hash)).map(|e| e.root)
    }

    /// Mirror of [`CrossShardMessage::verify_anchored`] for callers that only
    /// need the anchor verdict without the proof check.
    pub fn anchor_holds(
        &self,
        source_shard: ShardId,
        block_hash: &[u8; 32],
        claimed_root: &crate::cell::CellHash,
    ) -> bool {
        matches!(self.lookup(source_shard, block_hash), Some(r) if &r == claimed_root)
    }

    /// Record a finalized block WITH its full header, so the masterchain can
    /// publish a shard-head commitment for it (TON `shard_hashes`).
    ///
    /// The newest header wins: a header at a greater height replaces the
    /// recorded one and a header at the SAME height replaces it as well (the
    /// idempotent re-note of the same block), but a header at a LOWER height
    /// NEVER displaces a newer one — replaying an old block after a reorg
    /// must not roll the published head back.
    ///
    /// The anchor map is updated exactly as [`Self::note_finalized`] does, so
    /// recording a full header is a strict superset of the anchor-only note.
    pub fn note_finalized_commitment(&mut self, commitment: ShardHeaderCommitment) {
        self.apply_commitment(commitment, commitment.state_root);
        self.prune_anchors();
        self.persist();
    }

    /// Record a finalized header AND its post-apply anchor root in ONE
    /// mutation: the runtime's normal finalize/adopt path. Persists once
    /// (instead of the two snapshots a separate commitment + anchor note would
    /// enqueue), and leaves the map in the exact state a restart must see.
    pub fn note_finalized_commitment_with_anchor(
        &mut self,
        commitment: ShardHeaderCommitment,
        post_apply_root: crate::cell::CellHash,
    ) {
        self.apply_commitment(commitment, post_apply_root);
        self.prune_anchors();
        self.persist();
    }

    fn apply_commitment(
        &mut self,
        commitment: ShardHeaderCommitment,
        anchor_root: crate::cell::CellHash,
    ) {
        self.upsert_anchor(
            (commitment.shard_id, commitment.block_hash),
            anchor_root,
            commitment.height,
        );
        let replace = match self.latest.get(&commitment.shard_id) {
            Some(prev) => commitment.height >= prev.height,
            None => true,
        };
        if replace {
            self.latest.insert(commitment.shard_id, commitment);
        }
    }

    /// The latest finalized header of a shard, if this process finalized one.
    pub fn latest_header(&self, shard: ShardId) -> Option<&ShardHeaderCommitment> {
        self.latest.get(&shard)
    }

    /// The latest finalized header of every WORKCHAIN shard (id >= 1), in
    /// ascending shard order — the set a masterchain block publishes.
    ///
    /// The masterchain's own head is deliberately excluded: a block never
    /// commits to its own head, and the masterchain block itself IS the
    /// commitment.
    pub fn workchain_headers(&self) -> Vec<ShardHeaderCommitment> {
        self.latest
            .values()
            .filter(|h| h.shard_id != MASTERCHAIN_SHARD)
            .cloned()
            .collect()
    }

    /// Number of retained `(shard, block_hash) -> root` anchors (bounded by
    /// [`REGISTRY_ANCHOR_WINDOW`] + the latest-head anchor + the genesis cap,
    /// per shard).
    pub fn anchor_count(&self) -> usize {
        self.headers.len()
    }

    /// Drop every anchor and head, keeping the attached sinks. Used ONLY to
    /// fail closed (a corrupt persisted blob must not leave a partially
    /// hydrated registry that could accept a forged anchor).
    pub fn clear_anchors(&mut self) {
        self.headers.clear();
        self.latest.clear();
    }

    /// Attach a durable sink and immediately persist the current snapshot.
    ///
    /// Called at startup, after the store is open and (on restart) after the
    /// blob has been hydrated, so the first post-attach finalize extends the
    /// restored state instead of overwriting it with an empty one.
    pub fn attach_persistence(&mut self, sink: Arc<dyn FinalizedHeaderSink>) {
        if !self.sinks.iter().any(|s| Arc::ptr_eq(s, &sink)) {
            self.sinks.push(sink);
        }
        self.persist();
    }

    /// Deterministic anchor prune.
    ///
    /// Per shard, retain:
    ///   * all `REGISTRY_GENESIS_ANCHORS_PER_SHARD` lowest-hash height-0
    ///     anchors (plus the shard's latest head anchor even when it is
    ///     height 0) — genesis anchors are referenced by the first messages and
    ///     are never re-recorded;
    ///   * the `REGISTRY_ANCHOR_WINDOW` highest `(height, block_hash)` anchors.
    ///
    /// The rule reads only heights and hashes, never insertion order, so two
    /// nodes that finalized/adopted the same headers prune to byte-identical
    /// state even if they saw the blocks in a different order.
    pub fn prune_anchors(&mut self) {
        if self.headers.is_empty() {
            return;
        }
        let latest_hash: BTreeMap<ShardId, [u8; 32]> = self
            .latest
            .iter()
            .map(|(shard, c)| (*shard, c.block_hash))
            .collect();
        let mut by_shard: BTreeMap<ShardId, Vec<(AnchorKey, u64)>> = BTreeMap::new();
        for (key, entry) in &self.headers {
            by_shard
                .entry(key.0)
                .or_default()
                .push((*key, entry.height));
        }
        let mut keep: BTreeSet<AnchorKey> = BTreeSet::new();
        for (shard, entries) in by_shard {
            let mut genesis: Vec<(AnchorKey, u64)> = entries
                .iter()
                .filter(|(_, height)| *height == 0)
                .cloned()
                .collect();
            genesis.sort_by(|a, b| a.0 .1.cmp(&b.0 .1));
            let anchor_of_latest = latest_hash.get(&shard).copied();
            for (idx, (key, _)) in genesis.iter().enumerate() {
                if idx < REGISTRY_GENESIS_ANCHORS_PER_SHARD || anchor_of_latest == Some(key.1) {
                    keep.insert(*key);
                }
            }
            let mut live: Vec<(AnchorKey, u64)> = entries
                .into_iter()
                .filter(|(_, height)| *height > 0)
                .collect();
            live.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0 .1.cmp(&a.0 .1)));
            for (key, _) in live.into_iter().take(REGISTRY_ANCHOR_WINDOW) {
                keep.insert(key);
            }
            if let Some(hash) = anchor_of_latest {
                keep.insert((shard, hash));
            }
        }
        self.headers.retain(|key, _| keep.contains(key));
    }

    /// This registry's complete retained state as a delta (sorted, so the
    /// bytes and any later merge are deterministic).
    pub fn to_delta(&self) -> FinalizedHeaderDelta {
        FinalizedHeaderDelta {
            anchors: self
                .headers
                .iter()
                .map(|((shard, hash), entry)| (*shard, *hash, entry.height, entry.root))
                .collect(),
            latest: self.latest.values().copied().collect(),
        }
    }

    /// Apply a delta. Explicit conflict semantics (fail closed, no partial
    /// mutation):
    ///   * same `(shard, block_hash)` with a DIFFERENT root is an error — two
    ///     roots for one finalized block is exactly the forgery this registry
    ///     exists to refuse;
    ///   * same key with the same root keeps the greater height (a height-less
    ///     legacy note never erases the height a real finalize recorded);
    ///   * a head at a greater height replaces the older one, an older head
    ///     never rolls the head back, and a head at the SAME height with
    ///     different bytes is an error (two different heads for one height).
    pub fn apply_delta(&mut self, delta: FinalizedHeaderDelta) -> Result<(), String> {
        self.apply_delta_inner(delta, true)
    }

    fn apply_delta_inner(
        &mut self,
        delta: FinalizedHeaderDelta,
        persist: bool,
    ) -> Result<(), String> {
        // Validate BEFORE mutating: a conflict must leave the registry as it
        // was (fail closed), never half-merged.
        for (shard, hash, _, root) in &delta.anchors {
            if let Some(prev) = self.headers.get(&(*shard, *hash)) {
                if &prev.root != root {
                    return Err(format!(
                        "conflicting anchor for shard {shard} block {}: stored root differs from the applied one",
                        hex32(hash)
                    ));
                }
            }
        }
        for c in &delta.latest {
            if let Some(prev) = self.latest.get(&c.shard_id) {
                if prev.height == c.height && prev != c {
                    return Err(format!(
                        "conflicting finalized head for shard {} at height {}: two different headers",
                        c.shard_id, c.height
                    ));
                }
            }
        }
        for (shard, hash, height, root) in delta.anchors {
            match self.headers.get_mut(&(shard, hash)) {
                Some(entry) => {
                    entry.root = root;
                    if height > entry.height {
                        entry.height = height;
                    }
                }
                None => {
                    self.headers
                        .insert((shard, hash), AnchorEntry { root, height });
                }
            }
        }
        for c in delta.latest {
            let replace = match self.latest.get(&c.shard_id) {
                Some(prev) => c.height > prev.height,
                None => true,
            };
            if replace {
                self.latest.insert(c.shard_id, c);
            }
        }
        self.prune_anchors();
        if persist {
            self.persist();
        }
        Ok(())
    }

    /// Merge another registry's retained state. Same semantics as
    /// [`Self::apply_delta`].
    pub fn merge(&mut self, other: &FinalizedHeaderRegistry) -> Result<(), String> {
        self.apply_delta(other.to_delta())
    }

    /// Encode the registry as deterministic bincode bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let payload = RegistryPayloadV1 {
            anchors: self.to_delta().anchors,
            latest: self.latest.values().copied().collect(),
        };
        let payload_bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(REGISTRY_BLOB_LIMIT)
            .serialize(&payload)
            .map_err(|e| format!("encode finalized-header registry payload: {e}"))?;
        let checksum = registry_checksum(REGISTRY_SNAPSHOT_VERSION, &payload_bytes);
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(REGISTRY_BLOB_LIMIT)
            .serialize(&RegistrySnapshotV1 {
                version: REGISTRY_SNAPSHOT_VERSION,
                checksum,
                payload: payload_bytes,
            })
            .map_err(|e| format!("encode finalized-header registry: {e}"))
    }

    /// Decode a registry snapshot written by [`Self::to_bytes`].
    ///
    /// Any structural violation (unknown version, checksum mismatch, duplicate
    /// key/head, out-of-bound count, truncated/garbage bytes) is an error. The
    /// caller must treat the error as FAIL CLOSED:
    /// [`Self::restore_from_bytes`] does so by clearing the registry.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty finalized-header registry blob".to_string());
        }
        if bytes.len() as u64 > REGISTRY_BLOB_LIMIT {
            return Err(format!(
                "finalized-header registry blob of {} bytes exceeds the {} byte limit",
                bytes.len(),
                REGISTRY_BLOB_LIMIT
            ));
        }
        let snapshot: RegistrySnapshotV1 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(REGISTRY_BLOB_LIMIT)
            .deserialize(bytes)
            .map_err(|e| format!("decode finalized-header registry: {e}"))?;
        if snapshot.version != REGISTRY_SNAPSHOT_VERSION {
            return Err(format!(
                "unsupported finalized-header registry version {} (this node speaks {})",
                snapshot.version, REGISTRY_SNAPSHOT_VERSION
            ));
        }
        let expected = registry_checksum(snapshot.version, &snapshot.payload);
        if expected != snapshot.checksum {
            return Err(
                "finalized-header registry checksum mismatch (corrupt or forged blob)".to_string(),
            );
        }
        let payload: RegistryPayloadV1 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(REGISTRY_BLOB_LIMIT)
            .deserialize(&snapshot.payload)
            .map_err(|e| format!("decode finalized-header registry payload: {e}"))?;
        if payload.anchors.len() > REGISTRY_MAX_ANCHORS {
            return Err(format!(
                "finalized-header registry carries {} anchors (limit {})",
                payload.anchors.len(),
                REGISTRY_MAX_ANCHORS
            ));
        }
        if payload.latest.len() > REGISTRY_MAX_SHARDS {
            return Err(format!(
                "finalized-header registry carries {} shard heads (limit {})",
                payload.latest.len(),
                REGISTRY_MAX_SHARDS
            ));
        }
        let mut headers: BTreeMap<AnchorKey, AnchorEntry> = BTreeMap::new();
        for (shard, hash, height, root) in payload.anchors {
            if headers
                .insert((shard, hash), AnchorEntry { root, height })
                .is_some()
            {
                return Err(format!(
                    "duplicate finalized-header anchor for shard {shard} block {}",
                    hex32(&hash)
                ));
            }
        }
        let mut latest: BTreeMap<ShardId, ShardHeaderCommitment> = BTreeMap::new();
        for commitment in payload.latest {
            if latest.insert(commitment.shard_id, commitment).is_some() {
                return Err(format!(
                    "duplicate finalized head for shard {}",
                    commitment.shard_id
                ));
            }
        }
        let mut registry = Self {
            headers,
            latest,
            sinks: Vec::new(),
        };
        // A blob written by a future/other build may exceed this node's bound;
        // re-pruning keeps memory and every later snapshot inside it.
        registry.prune_anchors();
        Ok(registry)
    }

    /// Hydrate from persisted bytes, FAIL CLOSED: on any decode/merge error the
    /// registry is left EMPTY (loudly, by the caller) rather than keeping a
    /// partial state that could accept a forged anchor.
    pub fn restore_from_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        match Self::from_bytes(bytes) {
            Ok(snapshot) => {
                // Merge into a sink-less copy so a rejected merge cannot have
                // already enqueued a snapshot of the half-merged state.
                let mut merged = Self {
                    headers: self.headers.clone(),
                    latest: self.latest.clone(),
                    sinks: Vec::new(),
                };
                match merged.apply_delta_inner(snapshot.to_delta(), false) {
                    Ok(()) => {
                        self.headers = merged.headers;
                        self.latest = merged.latest;
                        Ok(())
                    }
                    Err(e) => {
                        self.clear_anchors();
                        Err(e)
                    }
                }
            }
            Err(e) => {
                self.clear_anchors();
                Err(e)
            }
        }
    }

    fn persist(&self) {
        if self.sinks.is_empty() {
            return;
        }
        match self.to_bytes() {
            Ok(bytes) => {
                for sink in &self.sinks {
                    sink.persist_finalized_headers(bytes.clone());
                }
            }
            // Never write an empty/replacement blob on an encode failure: the
            // previous (good) snapshot stays valid and the next finalize
            // retries.
            Err(e) => eprintln!("[xshard] refusing to persist finalized-header registry: {e}"),
        }
    }
}

/// SHA-256 checksum binding the schema version to one encoded payload.
fn registry_checksum(version: u32, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REGISTRY_SNAPSHOT_TAG);
    hasher.update(version.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Short hex rendering for conflict diagnostics (no logging crate dependency
/// in the sharding layer).
fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Process-shared finalized-header registry (C1 anchor plumbing). Every
/// shard runtime and state engine in the process holds the SAME `Arc`
/// (constructed once per process/cluster, passed explicitly — never a
/// global: independent test clusters must not mix their geneses).
/// The whole cross-shard replay state in one snapshot blob (audit F-I).
///
/// The engine's consumed set gates the actual credit at apply time; the
/// runtime's three sets gate proposal/validation (consumed filter), ack/bounce
/// linkage + timeout-bounce generation (produced), and completion marking
/// (completed). ALL of them are memory-only today, so a restart wiped them
/// and a replayed message passed every check: the target credited twice, or a
/// bounce refunded twice. Snapshotted height-keyed like every other domain;
/// restored on startup (full replay via `restore_cross_shard_replay`, engine
/// part in the load paths, runtime part where the runtime is constructed).
/// Sorted vecs (deterministic bytes); a missing entry means "empty", which is
/// also what a fresh process holds.
///
/// COMMITTED into `commitment_digest` (audit F1 fix) via
/// `commitment::write_cross_shard_domain`: a CONDITIONAL domain — all three
/// sets empty writes zero bytes, so existing chains (`COMMITMENT_VERSION`
/// unchanged) and every single-shard snapshot root byte-identically to
/// before, while any non-empty replay state moves the root. Two nodes with
/// identical blocks derive identical sets, so no consensus divergence can
/// arise from the sets themselves — and a node that drops them can no longer
/// agree with one that kept them under one root.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossShardReplaySnapshot {
    /// Engine credit gate (one entry per consumed inbound message).
    pub engine_consumed: Vec<CrossShardKey>,
    /// Runtime propose/validate filter mirror.
    pub runtime_consumed: Vec<CrossShardKey>,
    /// Outbounds this chain committed: (tx hash, transaction, height).
    pub produced: Vec<([u8; 32], Transaction, u64)>,
    /// Completed lifecycles (acked or bounced tx hashes).
    pub completed: Vec<[u8; 32]>,
    /// §9 CROSS-SHARD 2PC: the committed two-phase-commit records (the
    /// intermediate states of the cross-shard transfer lifecycle).
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a snapshot
    /// persisted before the 2PC existed ends its byte stream one field early.
    /// `serde(default)` covers the self-describing formats and the bincode
    /// path is covered by [`de_xpc_records`], which reads a missing trailing
    /// field as "no 2PC record" instead of failing the whole decode.
    #[serde(default, deserialize_with = "de_xpc_records")]
    pub xpc: Vec<crate::xshard2pc::XpcRecord>,
}

impl CrossShardKey {
    pub fn of(msg: &CrossShardMessage) -> Self {
        Self {
            source_shard: msg.source_shard,
            finalized_in_block: msg.finalized_in_block,
            msg_id: msg.msg_id,
        }
    }
}

/// Bincode-tolerant reader for the trailing `xpc` field of a cross-shard
/// replay snapshot.
///
/// A snapshot persisted BEFORE the 2PC existed ends its byte stream right
/// after `completed`. A missing trailing field means exactly one thing
/// ("this snapshot predates the 2PC"), so it decodes as the EMPTY record set
/// instead of failing the whole decode - a node must still be able to open
/// the chain it wrote before the upgrade. Every other error is propagated
/// unchanged (fail closed).
fn de_xpc_records<'de, D>(d: D) -> Result<Vec<crate::xshard2pc::XpcRecord>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Vec::<crate::xshard2pc::XpcRecord>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if super::block::legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(Vec::new())
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `xpc_phase` field of a
/// cross-shard message.
///
/// A message persisted BEFORE the 2PC existed ends its byte stream right
/// after `sender_scheme`. Bincode reports the missing trailing field as an
/// I/O end-of-file, which serde would normally propagate as a hard decode
/// error — an old chain would become unreadable and old messages received
/// over the wire would be rejected. A missing trailing field means exactly
/// one thing ("this message predates the 2PC"), so it decodes as the LEGACY
/// phase (`0`) instead of failing the whole decode. Every other error is
/// propagated unchanged (fail closed): a corrupt body must never be read as
/// "a legacy record".
fn de_xpc_phase<'de, D>(d: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match u8::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if super::block::legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(crate::xshard2pc::XPC_LEGACY)
            } else {
                Err(e)
            }
        }
    }
}

// ==================== §5 M3: shared sequencer + two-phase atomicity + L2 lane ====================
//
// SCOPE (§5 M3 core). Dynamic split/merge is OUT of scope (non-deterministic by
// load; `DynamicShardManager` wiring untouched). `Block` / `Transaction` gain NO
// new fields (bincode 1.3 compat): every new record rides the pre-existing
// `Block.cross_shard_out: Vec<CrossShardMessage>` field, and the ack/bounce
// kinds below reuse the pre-existing `CrossShardMessage` fields
// (`source_shard` / `target_shard` direction + `bounce` / `bounced` flags).
//
// 1. SHARED SEQUENCER (consensus-adjacent, deterministic). The old
//    `SharedSequencer::sequence_message` counter was Sim-only (call order =
//    whatever the simulator did). The consensus-adjacent rule is
//    [`SharedSequencer::assign_from_block`]: sequence numbers are assigned from
//    COMMITTED block content only, in a global order keyed by
//    `(source_height, source_shard, msg_id)`. Any node replaying the same
//    finalized blocks in `(height, shard)` order derives identical
//    `(CrossShardKey -> seq)` assignments. No wall-clock, no operator input,
//    no network read participates in the ordering rule. The watermark
//    (`note_finalized`) advances only from finalized block content.
// 2. TWO-PHASE ATOMICITY (ack/bounce). M2's source-debit is one-way. M3 adds:
//      * ACK: the target shard, having committed the consumption record,
//        publishes an ack (reversed direction, `bounced == false`). The source
//        shard commits the ack record; the transfer is then COMPLETE and no
//        bounce for it may ever be admitted.
//      * BOUNCE: when the target never consumes (failure/timeout), the source
//        shard commits a bounce-back record after a deterministic TIMEOUT
//        measured in HEIGHTS ([`CROSS_SHARD_TIMEOUT_HEIGHTS`]), refunding
//        `tx.amount` to `tx.from`. A bounce is valid iff the matching outbound
//        is committed on this chain, no ack/bounce for the same transaction
//        completed yet, and `at_height >= produce_height + TIMEOUT`.
//    Replay protection covers acks/bounces under the same [`CrossShardKey`]
//    discipline (each has a distinct `msg_id`), PLUS a per-transaction
//    completion guard (same `tx` hash can complete at most once even across
//    differing carrier hashes) enforced by the runtime.
//    KIND ENCODING (no new fields): with `S = tx.source_shard, T = tx.target_shard`
//      * transfer: `source == S && target == T && !bounced` (proof required);
//      * ack:      `source == T && target == S && !bounced && !bounce` (no proof;
//                  linkage to a committed outbound required);
//      * bounce:   `source == T && target == S && bounced && !bounce` (no proof;
//                  linkage + timeout required).
//    Control records (ack/bounce) MUST carry no Merkle proof: the state engine
//    credits any proof-carrying inbound to `tx.to`, so a proof-carrying
//    reversed-direction record would mint on the source shard. The runtime
//    refuses them (fail closed) and the engine skips proof-less records, which
//    is what makes the refund path safe without a state-engine change.
// 3. L2 SEQUENCING INTERFACE ([`L2Sequencer`] / [`L2Batch`]): a minimal,
//    documented append-only ordering service. Admission rules (contiguous
//    indices, payload-hash binding, signature verification) + ordering
//    guarantee (`(l2_id, batch_index)` FIFO). DA/bridging of L2 state is OUT
//    of scope: this is interface + ordering only; batch transactions reach
//    blocks through normal admission (no new `Block` fields).

/// Timeout for a cross-shard transfer, in SOURCE-shard heights.
///
/// A bounce-back refund for a transaction produced at source height `Hp` may
/// be committed in a source block at height `H` iff `H >= Hp + TIMEOUT`. Pure
/// heights, never seconds: every node applying the same source chain agrees
/// on `Hp` (the height that committed the outbound) and on `H` (the block
/// being validated), so the timeout verdict is deterministic. 64 heights is
/// far beyond any healthy consume+ack latency (2 heights in the honest flow)
/// and short enough that a failed transfer refunds promptly.
pub const CROSS_SHARD_TIMEOUT_HEIGHTS: u64 = 64;

/// True when a bounce-back for an outbound produced at `produce_height` may be
/// committed at `at_height`. Pure function of heights (no clock, no state).
pub fn bounce_eligible(produce_height: u64, at_height: u64) -> bool {
    at_height >= produce_height.saturating_add(CROSS_SHARD_TIMEOUT_HEIGHTS)
}

/// The M3 kind of a [`CrossShardMessage`], derived from its pre-existing
/// fields (direction relative to the carried transaction + flags) and, for
/// the §9 two-phase-commit records, from the `xpc_phase` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossShardKind {
    /// Value transfer `S -> T` (proof required).
    Transfer,
    /// Consumption receipt `T -> S` (linkage required, no value movement).
    Ack,
    /// Refund claim `T -> S` (linkage + timeout required, refunds `tx.from`).
    Bounce,
    /// §9 2PC PREPARE `S -> T` (the source escrows and asks the target to
    /// prepare; NO credit on the target).
    Prepare,
    /// §9 2PC PREPARE-ACK `T -> S` (the target's vote: "I am prepared, I will
    /// credit on the COMMIT"; proven against the target's committed state).
    PrepareAck,
    /// §9 2PC COMMIT `S -> T` (the source's decision; the target credits).
    Commit,
    /// §9 2PC ABORT-REQUEST `S -> T` (the source asks the target to abort a
    /// transfer it never prepared).
    AbortRequest,
    /// §9 2PC ABORT-ACK `T -> S` (the target's authorisation for the source's
    /// refund; proven against the target's committed state).
    AbortAck,
    /// Anything else (not committable; fail closed).
    Unknown,
}

impl CrossShardMessage {
    /// Classify this message without touching its bytes.
    pub fn kind(&self) -> CrossShardKind {
        let s = self.tx.source_shard;
        let t = self.tx.target_shard;
        if s == t {
            return CrossShardKind::Unknown;
        }
        // §9 2PC: a non-zero phase decides the kind on its own. The direction
        // must AGREE with the phase (the phase says who speaks to whom), or
        // the record is refused: a PREPARE travelling target -> source is not
        // a PREPARE, it is a forgery attempt.
        if self.xpc_phase != crate::xshard2pc::XPC_LEGACY {
            return match self.xpc_phase {
                crate::xshard2pc::XPC_PREPARE => {
                    if self.source_shard == s && self.target_shard == t {
                        CrossShardKind::Prepare
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_PREPARE_ACK => {
                    if self.source_shard == t && self.target_shard == s {
                        CrossShardKind::PrepareAck
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_COMMIT => {
                    if self.source_shard == s && self.target_shard == t {
                        CrossShardKind::Commit
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_ABORT_REQUEST => {
                    if self.source_shard == s && self.target_shard == t {
                        CrossShardKind::AbortRequest
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_ABORT_ACK => {
                    if self.source_shard == t && self.target_shard == s {
                        CrossShardKind::AbortAck
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                _ => CrossShardKind::Unknown,
            };
        }
        match (
            self.source_shard,
            self.target_shard,
            self.bounced,
            self.bounce,
        ) {
            (a, b, false, _) if a == s && b == t => CrossShardKind::Transfer,
            (a, b, false, false) if a == t && b == s => CrossShardKind::Ack,
            (a, b, true, false) if a == t && b == s => CrossShardKind::Bounce,
            _ => CrossShardKind::Unknown,
        }
    }

    /// True for a value transfer `S -> T` (the only M2 kind).
    pub fn is_transfer(&self) -> bool {
        self.kind() == CrossShardKind::Transfer
    }

    /// True for a consumption receipt `T -> S`.
    pub fn is_ack(&self) -> bool {
        self.kind() == CrossShardKind::Ack
    }

    /// True for a refund claim `T -> S`.
    pub fn is_bounce(&self) -> bool {
        self.kind() == CrossShardKind::Bounce
    }

    /// True for a §9 two-phase-commit record of any phase.
    pub fn is_xpc(&self) -> bool {
        self.xpc_phase != crate::xshard2pc::XPC_LEGACY
    }

    /// True for the §9 PREPARE record (`S -> T`).
    pub fn is_prepare(&self) -> bool {
        self.kind() == CrossShardKind::Prepare
    }

    /// True for the §9 PREPARE-ACK record (`T -> S`).
    pub fn is_prepare_ack(&self) -> bool {
        self.kind() == CrossShardKind::PrepareAck
    }

    /// True for the §9 COMMIT record (`S -> T`).
    pub fn is_commit(&self) -> bool {
        self.kind() == CrossShardKind::Commit
    }

    /// True for the §9 ABORT-REQUEST record (`S -> T`).
    pub fn is_abort_request(&self) -> bool {
        self.kind() == CrossShardKind::AbortRequest
    }

    /// True for the §9 ABORT-ACK record (`T -> S`).
    pub fn is_abort_ack(&self) -> bool {
        self.kind() == CrossShardKind::AbortAck
    }

    /// True for a record that NEVER moves value by itself: the legacy ack and
    /// bounce, and every §9 2PC control record.
    ///
    /// The state engine credits an inbound record to `tx.to` whenever it
    /// carries a Merkle proof, so a control record that carried one would MINT
    /// on the wrong shard. The engine therefore skips every control record
    /// and the runtime performs the value movement itself (the bounce refund,
    /// the 2PC commit credit) under the linkage rules.
    pub fn is_control(&self) -> bool {
        matches!(
            self.kind(),
            CrossShardKind::Ack
                | CrossShardKind::Bounce
                | CrossShardKind::PrepareAck
                | CrossShardKind::Commit
                | CrossShardKind::AbortRequest
                | CrossShardKind::AbortAck
        )
    }

    /// Build a §9 TWO-PHASE-COMMIT record.
    ///
    /// The message id commits to the PHASE, so the records of one transfer
    /// never collide in the transport mailbox (which is keyed by `msg_id`) and
    /// a replay of one phase can never be mistaken for another. The legacy
    /// `msg_id` computation is untouched: a legacy record keeps its
    /// byte-identical id (and therefore its byte-identical replay key).
    pub fn new_xpc(
        phase: u8,
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
        proof: Option<MerkleProof>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"XPC2");
        hasher.update([phase]);
        hasher.update(source_shard.to_be_bytes());
        hasher.update(target_shard.to_be_bytes());
        hasher.update(tx.compute_tx_hash());
        hasher.update(finalized_in_block);
        let msg_id = hasher.finalize().into();

        let mut m = Self::new(
            source_shard,
            target_shard,
            tx,
            source_state_root,
            finalized_in_block,
            proof,
        );
        m.msg_id = msg_id;
        // The legacy flags are unused by the 2PC records: `bounce` /
        // `bounced` stay at their neutral values so the legacy kind
        // derivation can never classify a 2PC record.
        m.bounce = false;
        m.bounced = false;
        m.source_balance = 0;
        m.xpc_phase = phase;
        m
    }

    /// Verify the §9 2PC STATE PROOF carried by this record.
    ///
    /// The proof is a Merkle inclusion proof of the 2PC state leaf of the
    /// carried transaction in the PEER's state trie, at the peer's committed
    /// state root. The leaf value is `phase || tx_hash`, and both halves are
    /// known to the verifier (the phase from the record's kind, the
    /// transaction hash from the carried transaction), so the proof is
    /// checkable by anyone holding the message.
    ///
    /// `phases` lists the phases that are acceptable for this record: the
    /// COMMIT record accepts PREPARED (the source escrowed) and COMMITTED
    /// (the source already decided), the PREPARE-ACK accepts PREPARED, the
    /// ABORT-ACK accepts ABORTED.
    ///
    /// SECURITY: the local `trusted` shortcut is IGNORED, exactly like
    /// [`Self::verify_inclusion_strict`] does for the legacy transfer. A 2PC
    /// control record moves value (the COMMIT credits the recipient, the
    /// ABORT-ACK refunds the escrow), so its proof must ALWAYS be checked
    /// against the peer's committed state root. The `trusted` flag is a
    /// locally-produced convenience; it is cleared on every wire decode
    /// (`network::parse_cross_shard_incoming`), so a peer can never set it -
    /// but a 2PC record that skipped the proof would be a mint vector, and
    /// the check is cheap.
    pub fn verify_xpc_proof(&self, phases: &[crate::xshard2pc::XpcPhase]) -> bool {
        // XSHARD INTEGRITY (untrusted boundary): same `msg_id` recompute as
        // `verify_inclusion_untrusted` — a 2PC record with a rebound id is
        // refused before any trie work.
        if !self.verify_msg_id() {
            return false;
        }
        let Some(proof) = &self.merkle_inclusion_proof else {
            return false;
        };
        let tx_hash = self.tx.compute_tx_hash();
        let key = crate::xshard2pc::xpc_state_key(&tx_hash);
        phases.iter().any(|phase| {
            let value = crate::xshard2pc::xpc_state_value(*phase, &tx_hash);
            PatriciaTrie::verify_merkle_proof(&self.source_state_root, &key, &value, proof)
        })
    }

    /// Anchored verification of a §9 2PC state proof: the proof must check
    /// out against a state root that a LOCALLY FINALIZED header of the
    /// peer's shard committed to.
    ///
    /// This is the C1 anchor applied to the 2PC: the peer's quorum signed the
    /// block that carries that state root, so the peer's vote (PREPARE-ACK /
    /// ABORT-ACK) cannot be forged by a malicious peer.
    pub fn verify_xpc_anchored(
        &self,
        registry: Option<&FinalizedHeaderRegistry>,
        phases: &[crate::xshard2pc::XpcPhase],
    ) -> bool {
        let Some(reg) = registry else {
            return false;
        };
        if !reg.anchor_holds(
            self.source_shard,
            &self.finalized_in_block,
            &self.source_state_root,
        ) {
            return false;
        }
        self.verify_xpc_proof(phases)
    }

    /// Build the ack for a consumed transfer. The ack travels `T -> S`
    /// carrying the SAME transaction (linkage is by `tx` hash), with
    /// `consumed_in` naming the target block that committed the consumption
    /// (part of the deterministic `msg_id`, identical on every node that
    /// applied the same target block). No proof: the engine skips proof-less
    /// inbound records, and the source validates by linkage, not by proof.
    pub fn new_ack(tx: Transaction, consumed_in: [u8; 32]) -> Self {
        let mut m = Self::new(
            tx.target_shard,
            tx.source_shard,
            tx,
            [0u8; 32],
            consumed_in,
            None,
        );
        m.bounce = false;
        m.bounced = false;
        m.source_balance = 0;
        m
    }

    /// Build the bounce-back refund claim for a transfer that never completed.
    /// Same shape as an ack but `bounced == true`; the source shard credits
    /// `tx.amount` back to `tx.from` when it commits this record (after the
    /// timeout rule passes). `refunded_at` should be the source head the
    /// refunding block extends (deterministic per height). No proof, same
    /// reason as [`Self::new_ack`].
    pub fn new_bounce(tx: Transaction, refunded_at: [u8; 32]) -> Self {
        let mut m = Self::new(
            tx.target_shard,
            tx.source_shard,
            tx,
            [0u8; 32],
            refunded_at,
            None,
        );
        m.bounce = false;
        m.bounced = true;
        m.source_balance = 0;
        m
    }

    /// Recompute the construction-time message id from the message body.
    ///
    /// THE untrusted-boundary check (see [`Self::verify_msg_id`]): every
    /// constructor ([`Self::new`], [`Self::new_xpc`], [`Self::new_ack`],
    /// [`Self::new_bounce`], [`Self::new_trusted`]) assigns exactly this
    /// value, using the legacy domain for pre-2PC records and the `XPC2`
    /// domain (with the phase byte) for §9 2PC records. The id commits to the
    /// source shard, the target shard, the FULL transaction hash and the
    /// finalizing source block — never to the proof, the balance or the local
    /// `trusted` flag. A phase flip (legacy <-> 2PC) therefore also mismatches:
    /// the recompute follows the CARRIED phase while construction followed the
    /// original one.
    pub fn expected_msg_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        if self.xpc_phase != crate::xshard2pc::XPC_LEGACY {
            hasher.update(b"XPC2");
            hasher.update([self.xpc_phase]);
        }
        hasher.update(self.source_shard.to_be_bytes());
        hasher.update(self.target_shard.to_be_bytes());
        hasher.update(self.tx.compute_tx_hash());
        hasher.update(self.finalized_in_block);
        hasher.finalize().into()
    }

    /// True when the carried `msg_id` matches the recomputed construction id.
    ///
    /// Fail-closed at EVERY untrusted boundary (wire decode, block adoption,
    /// apply): a mismatch means the carrier rebound the id to a different
    /// body and the message is refused, never credited.
    pub fn verify_msg_id(&self) -> bool {
        self.msg_id == self.expected_msg_id()
    }

    /// Canonical commitment bytes of the FULL message for the block hash.
    ///
    /// Covers every consensus-relevant field: direction, the whole carried
    /// transaction (INCLUDING its signature bytes, so a signature swap under
    /// an identical tx hash still moves the commitment), the inclusion/XPC
    /// proof, both committed roots, the balance, the bounce flags, the sender
    /// key binding and the 2PC phase.
    ///
    /// Deliberately EXCLUDES two fields:
    /// * `msg_id` — covered by the legacy `msg_id` list in the block hash
    ///   already; including it here would be a self-reference.
    /// * `trusted` — a LOCAL-only flag (in-process routing convenience, never
    ///   consensus): the producing node holds it true while every adopter
    ///   holds it false for the same body, so covering it would fork the block
    ///   hash between honest nodes. Verification ignores it on every
    ///   untrusted path regardless.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        // In-memory serialization of `Serialize` fields is infallible in
        // practice; on error the empty preimage still binds the tag (and the
        // block hash still binds the `msg_id` list), so fail-closed holds.
        bincode::serialize(&(
            self.source_shard,
            self.target_shard,
            &self.tx,
            &self.merkle_inclusion_proof,
            &self.source_state_root,
            &self.finalized_in_block,
            self.source_balance,
            self.bounce,
            self.bounced,
            &self.sender_pubkey_hash,
            &self.sender_scheme,
            self.xpc_phase,
        ))
        .unwrap_or_default()
    }

    /// Tagged digest of [`Self::commitment_bytes`], mixed into
    /// [`super::Block::compute_hash`] once per carried message (non-empty bodies
    /// only, so empty-cross-shard blocks hash byte-identically to before).
    pub fn message_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(XSHARD_FULL_COMMITMENT_TAG);
        let bytes = self.commitment_bytes();
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

// ==================== L2 sequencing interface ====================
//
// A minimal append-only ordering service through which an EXTERNAL L2 submits
// ordered batches for inclusion.
//
// * APPEND-ONLY: per L2, `batch_index` must be exactly the next expected
//   index — no gaps, no overwrites, no reordering. A batch that skips an
//   index is rejected until the missing one arrives; a duplicate index is
//   rejected.
// * ADMISSION: every batch binds its transactions by `payload_hash`
//   (recomputed and compared), every transaction signature must verify, and
//   batches are size-capped. Nothing unverifiable is ever queued.
// * ORDERING GUARANTEE: [`L2Sequencer::batches_for_inclusion`] yields pending
//   batches in canonical `(l2_id, batch_index)` order — FIFO per L2,
//   deterministic across L2s. A proposer pulling in that order gives every
//   node the same L2-derived prefix for the same pending set.
// * OUT OF SCOPE (explicit): DA/bridging of L2 state, execution of L2
//   semantics, and any `Block` format change. Batch transactions are ordinary
//   [`Transaction`]s and reach blocks through normal admission; this is
//   interface + ordering guarantees only.

/// Maximum transactions in one L2 batch (anti-DoS bound on a single submit).
pub const L2_MAX_TXS_PER_BATCH: usize = 1024;

/// One externally-submitted L2 batch: an ordered list of transactions with a
/// binding payload hash. Never embedded in `Block` (no format change); the
/// sequencer only orders batches, and inclusion reuses normal tx admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L2Batch {
    /// Which L2 this batch belongs to (namespaces the index sequence).
    pub l2_id: u32,
    /// Append-only position within `l2_id` (0-based, contiguous).
    pub batch_index: u64,
    /// The transactions, in submission order (inclusion must preserve it).
    pub txs: Vec<Transaction>,
    /// Binding commitment over `txs` (recomputed and checked at admission).
    pub payload_hash: [u8; 32],
}

impl L2Batch {
    /// Build a batch, computing the binding payload hash.
    pub fn new(l2_id: u32, batch_index: u64, txs: Vec<Transaction>) -> Self {
        let payload_hash = Self::payload_hash_of(&txs);
        Self {
            l2_id,
            batch_index,
            txs,
            payload_hash,
        }
    }

    /// The binding commitment: `sha256(count || tx_hash_0 || tx_hash_1 || ..)`.
    /// Order-sensitive, so a reordered batch has a different hash.
    pub fn payload_hash_of(txs: &[Transaction]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"STELLEREUM_L2_BATCH_V1");
        hasher.update((txs.len() as u64).to_be_bytes());
        for t in txs {
            hasher.update(t.compute_tx_hash());
        }
        hasher.finalize().into()
    }

    /// Admission verification: non-empty, size-capped, hash-bound, and every
    /// transaction signature verifies. Fails closed on any violation.
    pub fn verify(&self) -> Result<(), String> {
        if self.txs.is_empty() {
            return Err("L2 batch carries no transactions".to_string());
        }
        if self.txs.len() > L2_MAX_TXS_PER_BATCH {
            return Err(format!(
                "L2 batch of {} txs exceeds the cap of {}",
                self.txs.len(),
                L2_MAX_TXS_PER_BATCH
            ));
        }
        if self.payload_hash != Self::payload_hash_of(&self.txs) {
            return Err("L2 batch payload hash does not bind its transactions".to_string());
        }
        if !Transaction::verify_signatures_batch(&self.txs) {
            return Err("L2 batch contains a bad transaction signature".to_string());
        }
        Ok(())
    }
}

/// Append-only per-L2 batch sequencer. All state is a pure function of the
/// submitted batches (no clock, no network); ordering is the canonical
/// `(l2_id, batch_index)` order.
#[derive(Clone, Debug, Default)]
pub struct L2Sequencer {
    /// Next expected `batch_index` per L2 (starts at 0).
    expected: HashMap<u32, u64>,
    /// Admitted but not yet included, in canonical order.
    pending: std::collections::BTreeMap<(u32, u64), L2Batch>,
    /// Highest included `batch_index` per L2 (pruning watermark).
    included_through: HashMap<u32, u64>,
}

impl L2Sequencer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit one batch. Accepts it iff it verifies AND its index is exactly
    /// the next expected for its L2 (append-only: gaps and duplicates are
    /// rejected, never queued).
    pub fn submit_batch(&mut self, batch: L2Batch) -> Result<(), String> {
        batch.verify()?;
        let next = self.expected.get(&batch.l2_id).copied().unwrap_or(0);
        if batch.batch_index != next {
            return Err(format!(
                "L2 {} batch index {} is not the next expected ({next}): gaps and duplicates are rejected",
                batch.l2_id, batch.batch_index
            ));
        }
        self.pending
            .insert((batch.l2_id, batch.batch_index), batch.clone());
        self.expected.insert(batch.l2_id, next + 1);
        Ok(())
    }

    /// The next expected batch index for an L2 (0 for a never-seen L2).
    pub fn expected_index(&self, l2_id: u32) -> u64 {
        self.expected.get(&l2_id).copied().unwrap_or(0)
    }

    /// Pending batches in canonical inclusion order (`(l2_id, batch_index)`
    /// ascending), up to `limit`. A proposer taking a prefix of this list
    /// preserves the ordering guarantee.
    pub fn batches_for_inclusion(&self, limit: usize) -> Vec<L2Batch> {
        self.pending.values().take(limit).cloned().collect()
    }

    /// Number of admitted-but-unincluded batches.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Mark batches through `through_index` (inclusive) for `l2_id` as
    /// included: drops them from pending and advances the prune watermark.
    /// Only moves forward (a stale mark is a no-op, never a rewind).
    pub fn mark_included(&mut self, l2_id: u32, through_index: u64) {
        let cur = self.included_through.get(&l2_id).copied().unwrap_or(0);
        // `through_index` is inclusive; the watermark counts included batches.
        let want = through_index.saturating_add(1);
        if want <= cur {
            return;
        }
        self.included_through.insert(l2_id, want);
        self.pending
            .retain(|(id, idx), _| !(*id == l2_id && *idx <= through_index));
    }

    /// How many batches of `l2_id` have been marked included (0 if none).
    pub fn included_count(&self, l2_id: u32) -> u64 {
        self.included_through.get(&l2_id).copied().unwrap_or(0)
    }
}
