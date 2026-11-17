use super::topology::{ShardId, MASTERCHAIN_SHARD};
use super::transaction::Transaction;
use super::xshard::{CrossShardKey, CrossShardMessage};
use crate::cell::CellHash;
use crate::post_quantum::FalconKeypair;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// The shard-head commitment published by a MASTERCHAIN block (the TON
/// `shard_hashes` model).
///
/// A masterchain block commits to the LATEST finalized header of every
/// workchain shard: which shard, at which height, which block hash, which
/// state root and when. The commitment rides INSIDE the block body, so it is
/// covered by [`Block::compute_hash`] and therefore signed by the BFT quorum
/// — a validator can prove "shard 1 was at height 42 with THIS state root"
/// from a single masterchain block, without ever having seen the source
/// shard's chain. That is what makes cross-shard proofs possible: an inbound
/// message's `source_state_root` is checked against the committed shard head
/// instead of against a locally trusted root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardHeaderCommitment {
    /// The shard this head belongs to (never the masterchain itself).
    pub shard_id: ShardId,
    /// The height of the committed shard block.
    pub height: u64,
    /// The hash of the committed shard block.
    pub block_hash: [u8; 32],
    /// The state root AFTER applying the committed shard block.
    pub state_root: [u8; 32],
    /// The timestamp of the committed shard block.
    pub timestamp: u64,
}

impl ShardHeaderCommitment {
    /// The canonical commitment bytes of one shard head.
    ///
    /// Every field is fixed-width and written big-endian, so the field
    /// boundaries are unambiguous and no two different heads can produce the
    /// same preimage. The set is domain-separated by
    /// [`SHARD_HEADERS_COMMITMENT_TAG`] where it enters the block hash.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 32 + 32 + 8);
        out.extend_from_slice(&self.shard_id.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out
    }
}

/// Domain separator for the shard-head commitment inside a block hash.
///
/// Versioning the block-commitment scheme is what keeps a block that
/// publishes no shard head hashing EXACTLY as it did before the field
/// existed: the commitment is only mixed in when the set is non-empty.
pub const SHARD_HEADERS_COMMITMENT_TAG: &[u8; 8] = b"SHARDHDR";

/// Domain separator for the TRANSACTION-ORDER commitment inside a block hash.
///
/// The order commitment is the order Merkle root over the block's transaction
/// list, in execution order (see [`crate::mev::compute_order_merkle_root`]). It
/// is mixed into the block hash under this tag, so the BFT quorum that signs
/// the block hash signs the ORDERING too: a proposer cannot reorder the block
/// after the votes, and every validator re-computes the root from the
/// proposed body and refuses a proposal that does not match.
pub const ORDER_MERKLE_COMMITMENT_TAG: &[u8; 8] = b"ORDROOT1";

/// Domain separator for the EPOCH-KEY commitment inside a block hash.
///
/// The epoch-key commitment is the commitment to the MEV epoch key that
/// sealed transactions of this epoch are encrypted to (see
/// [`crate::mev_epoch`]). It is mixed into the block hash under this tag,
/// so the BFT quorum that signs the block hash signs the epoch key too: a
/// wallet (or a light client) can take the epoch key from a full node and
/// check it against the chain.
pub const EPOCH_KEY_COMMITMENT_TAG: &[u8; 8] = b"EPKEYC01";

/// Domain separator for the canonical downtime-evidence QC inside a block hash.
///
/// The `last_qc` certificate (the precommit QC that decided height-1) is
/// mixed into the block hash under this tag, so the BFT quorum that signs
/// the block hash signs the downtime evidence too: a proposer cannot swap
/// the evidence after the votes, and the evidence is byte-identical on every
/// node that applies the block (W10.5 canonical-attribution fix).
pub const LAST_QC_COMMITMENT_TAG: &[u8; 8] = b"LASTQC01";

/// Domain separator for the EPOCH-MMR commitment inside a block hash.
///
/// The epoch-MMR root is the Merkle-Mountain-Range root over the PREVIOUS
/// epoch's 128 finalized block hashes (see [`crate::mmr`]). It is mixed into
/// the block hash under this tag, so the BFT quorum that signs the block
/// hash signs the epoch root too: a bridge (or a light client) can anchor on
/// one 32-byte root per epoch instead of 128 individual checkpoints.
pub const MMR_EPOCH_COMMITMENT_TAG: &[u8; 8] = b"MMRROOT1";

/// Domain separator for the FULL-MESSAGE cross-shard commitment inside a block hash.
///
/// The commitment binds every consensus-relevant byte of every outbound
/// cross-shard message (see [`super::CrossShardMessage::message_commitment`]), so the
/// BFT quorum that signs the block hash signs the message BODIES too: a
/// proposer cannot swap a message body under a voted `msg_id`, and a validator
/// that recomputes the commitment from the proposed body refuses the swap.
/// Mixed into [`Block::compute_hash`] ONLY for a non-empty `cross_shard_out`
/// (see the version rule there): empty-cross-shard blocks hash byte-identically
/// to before this commitment existed.
pub const XSHARD_FULL_COMMITMENT_TAG: &[u8; 8] = b"XSHARD01";

/// Domain separator for the CN-VRF v3 trailing block payload inside a block hash.
///
/// Mixed into [`Block::compute_hash`] ONLY when `cnvrf_v3` is `Some(...)`, so
/// every block with `cnvrf_v3: None` (including all legacy blocks) keeps its
/// pre-existing block hash byte-for-byte.
pub const CNVRF_V3_COMMITMENT_TAG: &[u8; 8] = b"CNVRFV31";

mod bytes48_serde {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(48)?;
        for byte in val {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 48];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "a 48-byte array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 48];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(48, V)
    }
}

mod opt_bytes48_serde {
    use super::bytes48_serde;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    struct Bytes48Ref<'a>(&'a [u8; 48]);
    impl Serialize for Bytes48Ref<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            bytes48_serde::serialize(self.0, s)
        }
    }

    struct Bytes48Owned([u8; 48]);
    impl<'de> Deserialize<'de> for Bytes48Owned {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            bytes48_serde::deserialize(d).map(Bytes48Owned)
        }
    }

    pub fn serialize<S: Serializer>(val: &Option<[u8; 48]>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(arr) => s.serialize_some(&Bytes48Ref(arr)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 48]>, D::Error> {
        Option::<Bytes48Owned>::deserialize(d).map(|opt| opt.map(|w| w.0))
    }
}

/// Epoch-boundary MinRoot VDF beacon carried inside a CN-VRF v3 block payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochVdfBeacon {
    pub epoch: u64,
    #[serde(with = "bytes48_serde")]
    pub raw_seed: [u8; 48],
    pub proof: crate::minroot_vdf::MinRootProof,
}

/// Trailing CN-VRF v3 consensus payload carried by a [`Block`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnVrfV3BlockPayload {
    #[serde(with = "opt_bytes48_serde")]
    pub reveal: Option<[u8; 48]>,
    pub commits: Vec<crate::cn_vrf::CommitCarrierV3>,
    pub epoch_vdf: Option<EpochVdfBeacon>,
}

impl CnVrfV3BlockPayload {
    /// Returns `true` when no reveal, commits, or epoch VDF beacon are present.
    pub fn is_empty(&self) -> bool {
        self.reveal.is_none() && self.commits.is_empty() && self.epoch_vdf.is_none()
    }

    /// Canonical commitment bytes over all fields of this payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.reveal {
            None => out.push(0u8),
            Some(rev) => {
                out.push(1u8);
                out.extend_from_slice(rev);
            }
        }
        let mut commits: Vec<&crate::cn_vrf::CommitCarrierV3> = self.commits.iter().collect();
        commits.sort_by(|a, b| {
            a.validator_id
                .cmp(&b.validator_id)
                .then_with(|| a.epoch_n.cmp(&b.epoch_n))
                .then_with(|| a.anchors.cmp(&b.anchors))
                .then_with(|| a.sig.cmp(&b.sig))
        });
        out.extend_from_slice(&(commits.len() as u32).to_be_bytes());
        for c in commits {
            out.extend_from_slice(&c.validator_id);
            out.extend_from_slice(&c.epoch_n.to_be_bytes());
            for anchor in &c.anchors {
                out.extend_from_slice(anchor);
            }
            out.extend_from_slice(&(c.sig.len() as u32).to_be_bytes());
            out.extend_from_slice(&c.sig);
        }
        match &self.epoch_vdf {
            None => out.push(0u8),
            Some(vdf) => {
                out.push(1u8);
                out.extend_from_slice(&vdf.epoch.to_be_bytes());
                out.extend_from_slice(&vdf.raw_seed);
                out.extend_from_slice(&vdf.proof.steps.to_be_bytes());
                out.extend_from_slice(&vdf.proof.final_xy.0);
                out.extend_from_slice(&vdf.proof.final_xy.1);
                out.extend_from_slice(&(vdf.proof.checkpoints.len() as u32).to_be_bytes());
                for &(step_idx, ref x_bytes, ref y_bytes) in &vdf.proof.checkpoints {
                    out.extend_from_slice(&step_idx.to_be_bytes());
                    out.extend_from_slice(x_bytes);
                    out.extend_from_slice(y_bytes);
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub shard_id: ShardId,
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub state_root: CellHash,
    pub transactions: Vec<Transaction>,
    pub cross_shard_out: Vec<CrossShardMessage>,
    pub timestamp: u64,
    pub proposer: [u8; 32],
    pub validator_signatures: Vec<([u8; 32], Vec<u8>)>,
    /// The precommit quorum certificate that finalized this block, if any.
    /// Attached at finalization time. Deliberately EXCLUDED from `compute_hash`
    /// (like `validator_signatures`): it is evidence ABOUT the block, decided by
    /// a quorum that only exists after the block hash is fixed. Including it in
    /// the hash would make finalization change the block's identity.
    /// Block sync verifies this QC instead of trusting bare signatures, because
    /// vote signatures are over `vote_sign_bytes`, not over the block hash, and
    /// can never verify as block signatures.
    pub precommit_qc: Option<crate::consensus::QuorumCertificate>,
    /// The shard-head commitments published by this block (TON `shard_hashes`).
    ///
    /// ONLY a masterchain block carries them: one entry per WORKCHAIN shard
    /// (id >= 1), each naming the latest finalized header of that shard
    /// (height, block hash, state root, timestamp). A workchain block commits
    /// to nothing but its own body, and a masterchain block of a single-shard
    /// process has no workchain shard to speak of — so the set is empty there
    /// and the legacy block hash stays byte-identical.
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed simply ends its byte stream one field
    /// early. `serde(default)` covers the self-describing formats, and the
    /// bincode path is covered by [`de_shard_headers`], which reads a missing
    /// trailing field as "this block predates the commitment" instead of
    /// failing the whole decode.
    ///
    /// The field is ALWAYS encoded (never skipped): bincode is positional, so
    /// omitting a field would make every NESTED block (a batch of proposals,
    /// a block inside a message) misread the next element's bytes as the
    /// missing field. The cost is 8 bytes per block (an empty length
    /// prefix) — and the block HASH is untouched, because the commitment is
    /// only mixed in for a non-empty set.
    #[serde(default, deserialize_with = "de_shard_headers")]
    pub shard_headers: Vec<ShardHeaderCommitment>,
    /// The TRANSACTION-ORDER commitment of this block: the order Merkle root
    /// over this block's transaction list, in execution order.
    ///
    /// It is a CONSENSUS commitment, not a local note: the root is mixed into
    /// [`Block::compute_hash`] under [`ORDER_MERKLE_COMMITMENT_TAG`], so the
    /// quorum that signs the block hash signs the ORDERING. A validator
    /// re-computes the root from the proposed body
    /// ([`crate::mev::compute_order_merkle_root`]) and REFUSES the proposal
    /// when it does not match — a proposer therefore cannot reorder a block
    /// after it has been voted on.
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed simply ends its byte stream one field
    /// early. `serde(default)` covers the self-describing formats, and the
    /// bincode path is covered by [`de_order_merkle_root`], which reads a
    /// missing trailing field as "this block predates the commitment"
    /// (the all-zero root) instead of failing the whole decode.
    ///
    /// The all-zero root is ALSO what a block with NO transactions carries:
    /// there is no order to commit, so the commitment is empty by definition
    /// (see [`crate::mev::compute_order_merkle_root`]). The block hash mixes
    /// the root in only when it is non-zero, so a legacy block (no root) and
    /// an empty block keep their pre-existing block hashes byte-for-byte.
    #[serde(default, deserialize_with = "de_order_merkle_root")]
    pub order_merkle_root: [u8; 32],
    /// The EPOCH-KEY commitment of this block: the commitment to the MEV
    /// epoch key that sealed transactions of this epoch are encrypted to
    /// (see [`crate::mev_epoch`]).
    ///
    /// It is `H(domain || epoch || epoch public key || committee hash ||
    /// threshold)` (see [`crate::mev_epoch::epoch_key_commitment`]), so a
    /// light client (or a wallet) can take the epoch key from a full node
    /// and CHECK it against the chain: the announcement must hash to the
    /// committed value. That is what makes the epoch key a CONSENSUS value
    /// instead of "whatever this node believes".
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed simply ends its byte stream one field
    /// early. `serde(default)` covers the self-describing formats, and the
    /// bincode path is covered by [`de_epoch_key_commitment`], which reads a
    /// missing trailing field as "this block predates the commitment" (the
    /// all-zero value) instead of failing the whole decode.
    ///
    /// The all-zero value is ALSO what a block of an epoch whose committee
    /// has no key carries (no DKG completed, so there is nothing to
    /// commit to), and the block hash mixes the commitment in only when it
    /// is non-zero — a legacy block (no commitment) keeps its pre-existing
    /// block hash byte-for-byte.
    #[serde(default, deserialize_with = "de_epoch_key_commitment")]
    pub epoch_key_commitment: [u8; 32],
    /// The PRECOMMIT quorum certificate that decided the PARENT block
    /// (height-1), embedded by the proposer.
    ///
    /// CANONICAL DOWNTIME EVIDENCE (W10.5 activation-race fix, live
    /// 2026-10-23 #292785/#292786): downtime attribution used to read the
    /// LOCALLY-ASSEMBLED `precommit_qc` attached at finalization time, so two
    /// nodes that finalized the same block with different quorate QC subsets
    /// (e.g. {A,C} vs {A,B,C} — both pass the same quorum) bumped different
    /// `missed` counters in the committed staking ledger and forked the state
    /// root permanently. The evidence is now chosen ONCE, by the proposer of
    /// this block, from the QC that decided the parent — every node that
    /// applies this block attributes the SAME evidence and converges.
    /// `precommit_qc` stays as the finality proof (light clients, checkpoints,
    /// sync); it is no longer evidence for slashing.
    ///
    /// CONSENSUS commitment: the certificate is mixed into
    /// [`Block::compute_hash`] under [`LAST_QC_COMMITMENT_TAG`], so the quorum
    /// that signs the block hash signs the evidence too, and validators
    /// re-verify the embedded QC against the validator set in force at
    /// height-1 before prevoting (see
    /// [`crate::runtime::ValidatorRuntime::check_last_qc_evidence`]).
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed ends its byte stream one field early.
    /// `serde(default)` covers the self-describing formats, and the bincode
    /// path is covered by [`de_last_qc`]. A missing trailing field decodes as
    /// `None` ("predates canonical evidence"); the transition then skips
    /// downtime attribution for that height (replay of pre-upgrade history
    /// falls back to the attached `precommit_qc` — see
    /// `replay_historical_block`). The block HASH mixes the certificate in
    /// only when present, so every pre-existing block keeps its hash
    /// byte-for-byte.
    #[serde(default, deserialize_with = "de_last_qc")]
    pub last_qc: Option<crate::consensus::QuorumCertificate>,
    /// The EPOCH-MMR root committed by this block: the MMR root over the
    /// PREVIOUS epoch's 128 finalized block hashes (see [`crate::mmr`]).
    ///
    /// ONLY the first masterchain block of an epoch carries it (height H
    /// with `H > 0` and `H % 128 == 0` commits epoch `H / 128 - 1` — see
    /// [`crate::mmr::commits_epoch_root`]). Committing the *previous* epoch
    /// keeps the commitment non-circular: a block never commits to a root
    /// that includes its own hash. Every other block carries zero.
    ///
    /// It is a CONSENSUS commitment, not a local note: the root is mixed
    /// into [`Block::compute_hash`] under [`MMR_EPOCH_COMMITMENT_TAG`], so
    /// the quorum that signs the block hash signs the epoch root, and a
    /// validator that knows the epoch's 128 bodies re-computes the root and
    /// REFUSES a proposal that commits a different one (a validator that
    /// does not know them yet accepts — the commitment is still checked by
    /// the quorum that signs the block; see
    /// [`crate::runtime::ValidatorRuntime::check_epoch_mmr_commitment`]).
    /// A workchain block that carries a non-zero root is refused (only the
    /// masterchain commits epochs).
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed ends its byte stream one field early.
    /// `serde(default)` covers the self-describing formats, and the bincode
    /// path is covered by [`de_mmr_epoch_root`]. A missing trailing field
    /// decodes as the all-zero root ("predates the epoch MMR"). The block
    /// HASH mixes the root in only when it is non-zero, so every
    /// pre-existing block keeps its hash byte-for-byte.
    ///
    /// COMPATIBILITY ARGUMENT (why this does not fork the live chain):
    ///
    /// * Hash stability: with a zero root the preimage — and therefore the
    ///   hash, the proposer signature and every vote/QC over it — is
    ///   byte-identical to the pre-MMR layout. All history, all checkpoints
    ///   and all signatures agreed before the upgrade keep verifying.
    /// * Store readability: a body persisted before the field existed
    ///   decodes tolerantly (inside `with_legacy_block_tolerance`), so an
    ///   upgraded node replays its old chain instead of re-genesising.
    /// * Fail-closed wire: like every trailing field before it, the wire
    ///   path decodes strictly. A node that has not upgraded does NOT
    ///   "verify the parts it understands" of a block carrying a root it
    ///   cannot interpret — it rejects the message, loudly, instead of
    ///   agreeing to a block identity it computed differently. Mixed-version
    ///   gossip therefore fails closed, never silently forks.
    /// * Coordinated activation: non-zero roots begin only after a
    ///   coordinated all-validators upgrade (the same rollout rule as the
    ///   order commitment and the sortition schedule). Until then — and
    ///   whenever a proposer does not know the epoch's 128 bodies (pruned,
    ///   freshly restarted) — the boundary block carries zero and hashes
    ///   exactly like a legacy block. A zero root at a boundary height is
    ///   valid; it means "not committed", and light clients must treat it
    ///   as such.
    #[serde(default, deserialize_with = "de_mmr_epoch_root")]
    pub mmr_epoch_root: [u8; 32],
    /// Trailing CN-VRF v3 consensus payload (proposer hash-chain reveal,
    /// epoch-ahead validator commits, and optional epoch-boundary MinRoot VDF
    /// beacon).
    ///
    /// BACKWARD COMPATIBILITY: trailing field with `serde(default)` +
    /// [`de_cnvrf_v3`]. Legacy blocks decoded under `with_legacy_block_tolerance`
    /// decode missing trailing bytes as `None`, while strict wire decoding fails
    /// closed. Mixed into [`Block::compute_hash`] ONLY when `Some(...)`.
    #[serde(default, deserialize_with = "de_cnvrf_v3")]
    pub cnvrf_v3: Option<CnVrfV3BlockPayload>,
}

impl Default for Block {
    /// The neutral block: no body, no commitments, masterchain shard.
    ///
    /// `Default` exists so that a struct literal can be written as
    /// `Block { height: 7, ..Default::default() }`: the functional-update
    /// syntax fills EVERY field the literal does not mention, so adding a
    /// field to [`Block`] can no longer break the call sites that did not
    /// know about it yet.
    ///
    /// The two commitment fields are NOT left to a caller to invent:
    /// [`Block::new_for_test`] derives the order commitment from the body, and
    /// [`Block::recompute_order_commitment`] re-derives it on demand. A block
    /// built through the plain `Default` carries the all-zero order root,
    /// which is exactly what an EMPTY block commits to.
    fn default() -> Self {
        Self {
            shard_id: MASTERCHAIN_SHARD,
            height: 0,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: Vec::new(),
            cross_shard_out: Vec::new(),
            timestamp: 0,
            proposer: [0u8; 32],
            validator_signatures: Vec::new(),
            precommit_qc: None,
            last_qc: None,
            shard_headers: Vec::new(),
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
        }
    }
}

thread_local! {
    /// Whether a block body may be decoded with the LEGACY shape (the
    /// trailing commitment fields absent).
    ///
    /// The tolerance exists ONLY for bodies PERSISTED before those fields
    /// existed. It must never apply to a body that arrives over the wire: a
    /// truncated message would then decode as a valid block with an empty
    /// shard-head set and an all-zero order root — i.e. a malformed message
    /// silently reinterpreted as a DIFFERENT block. The wire path therefore
    /// decodes STRICTLY (fail closed) and only the local store opts into the
    /// legacy shape.
    static LEGACY_BLOCK_TOLERANCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with the legacy block shape tolerated.
///
/// Thread-scoped on purpose: the flag is process-global state and the store
/// is read from many threads, so it must not leak into a concurrent decode of
/// a WIRE body (which must stay strict). The closure is synchronous, so no
/// await can observe the flag half-set.
pub fn with_legacy_block_tolerance<T>(f: impl FnOnce() -> T) -> T {
    LEGACY_BLOCK_TOLERANCE.with(|c| {
        let prev = c.replace(true);
        let out = f();
        c.set(prev);
        out
    })
}

/// True when the legacy block shape is tolerated on this thread.
pub(super) fn legacy_block_tolerance() -> bool {
    LEGACY_BLOCK_TOLERANCE.with(|c| c.get())
}

/// Bincode-tolerant reader for the trailing `order_merkle_root` field of a
/// block.
///
/// A block persisted BEFORE the order commitment existed ends its byte stream
/// right after `shard_headers`. Bincode reports the missing trailing field
/// as an I/O end-of-file, which serde would normally propagate as a hard
/// decode error — an old chain would become unreadable and old blocks
/// received over the wire would be rejected. A missing trailing field means
/// exactly one thing ("this block predates the commitment"), so it decodes as
/// the ALL-ZERO root. Every other error is propagated unchanged (fail
/// closed): a corrupt body must never be read as "no order commitment".
fn de_order_merkle_root<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <[u8; 32]>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            // The EOF shows up in two shapes depending on the backend: serde's
            // own "end of file" and bincode's wrapped I/O error ("failed to
            // fill whole buffer" — `read_exact` on a short buffer). Both mean
            // the byte stream ended before this trailing field.
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok([0u8; 32])
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `epoch_key_commitment` field of a
/// block.
///
/// A block persisted BEFORE the epoch-key commitment existed ends its byte
/// stream right after `order_merkle_root`. Bincode reports the missing
/// trailing field as an I/O end-of-file, which serde would normally
/// propagate as a hard decode error — an old chain would become unreadable
/// and old blocks received over the wire would be rejected. A missing
/// trailing field means exactly one thing ("this block predates the
/// commitment"), so it decodes as the ALL-ZERO value. Every other error is
/// propagated unchanged (fail closed): a corrupt body must never be read as
/// "this block commits to no epoch key".
fn de_epoch_key_commitment<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <[u8; 32]>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok([0u8; 32])
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `last_qc` field of a block.
///
/// A block persisted BEFORE canonical downtime evidence existed ends its byte
/// stream right after `epoch_key_commitment`. Bincode reports the missing
/// trailing field as an I/O end-of-file, which serde would normally
/// propagate as a hard decode error — an old chain would become unreadable
/// and old blocks received over the wire would be rejected. A missing
/// trailing field means exactly one thing ("this block predates canonical
/// evidence"), so it decodes as `None`. Every other error is propagated
/// unchanged (fail closed): a corrupt body must never be read as "no
/// evidence".
fn de_last_qc<'de, D>(d: D) -> Result<Option<crate::consensus::QuorumCertificate>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<crate::consensus::QuorumCertificate>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `mmr_epoch_root` field of a block.
///
/// A block persisted BEFORE the epoch MMR existed ends its byte stream right
/// after `last_qc`. Bincode reports the missing trailing field as an I/O
/// end-of-file, which serde would normally propagate as a hard decode error
/// — an old chain would become unreadable. A missing trailing field means
/// exactly one thing ("this block predates the epoch MMR"), so it decodes as
/// the ALL-ZERO root. Every other error is propagated unchanged (fail
/// closed): a corrupt body must never be read as "no epoch commitment".
fn de_mmr_epoch_root<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <[u8; 32]>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok([0u8; 32])
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `cnvrf_v3` field of a block.
///
/// A block persisted BEFORE CN-VRF v3 existed ends its byte stream right
/// after `mmr_epoch_root`. Under `legacy_block_tolerance()`, a missing trailing
/// field decodes as `None`. Strict wire decoding propagates every error
/// unchanged (fail closed).
fn de_cnvrf_v3<'de, D>(d: D) -> Result<Option<CnVrfV3BlockPayload>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<CnVrfV3BlockPayload>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `shard_headers` field of a block.
///
/// A block persisted BEFORE the shard-head commitment existed ends its byte
/// stream right after `precommit_qc`. Bincode reports the missing trailing
/// field as an I/O end-of-file, which serde would normally propagate as a
/// hard decode error — an old chain would become unreadable and old blocks
/// received over the wire would be rejected. A missing trailing field means
/// exactly one thing ("this block commits to no shard head"), so it decodes
/// as the EMPTY set. Every other error is propagated unchanged (fail closed):
/// a corrupt body must never be read as "no shard heads".
fn de_shard_headers<'de, D>(d: D) -> Result<Vec<ShardHeaderCommitment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Vec::<ShardHeaderCommitment>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            // The EOF shows up in two shapes depending on the backend:
            // serde's own "end of file" and bincode's wrapped I/O error
            // ("failed to fill whole buffer" — `read_exact` on a short
            // buffer). Both mean the same thing here: the byte stream ended
            // before this trailing field.
            let msg = e.to_string();
            if legacy_block_tolerance()
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

impl Block {
    /// A block with the consensus commitments DERIVED from its body.
    ///
    /// THIS is the constructor every example, bench and test should use. The
    /// block carries two commitments that are DERIVED from the body rather
    /// than chosen by the caller:
    ///
    /// * the transaction-order commitment ([`Block::order_merkle_root`]),
    ///   recomputed here from `transactions` — a block whose order root
    ///   disagrees with its body is REFUSED by the validator
    ///   (`crate::runtime::ConsensusRuntime::check_order_commitment`), so a
    ///   caller must never have to remember to set it;
    /// * the shard-head set ([`Block::shard_headers`]), empty here (a
    ///   workchain block commits to no shard head).
    ///
    /// Because every field that is not part of the identity of the block is
    /// either defaulted or derived, adding a field to [`Block`] no longer
    /// breaks the call sites: they call this constructor instead of spelling
    /// a struct literal.
    /// Test-only constructor: absent from production builds
    /// (`any(test, debug_assertions)` only).
    #[cfg(any(test, debug_assertions))]
    pub fn new_for_test(
        shard_id: ShardId,
        height: u64,
        prev_hash: [u8; 32],
        state_root: CellHash,
        transactions: Vec<Transaction>,
    ) -> Self {
        let mut b = Self {
            shard_id,
            height,
            prev_hash,
            state_root,
            transactions,
            ..Self::default()
        };
        b.recompute_order_commitment();
        b
    }

    /// Recompute the transaction-order commitment from the body.
    ///
    /// The root is a PURE function of the transaction list (see
    /// [`crate::mev::compute_order_merkle_root`]), so every node derives the
    /// same value from the same body. Call it after mutating
    /// [`Block::transactions`].
    pub fn recompute_order_commitment(&mut self) {
        self.order_merkle_root = crate::mev::compute_order_merkle_root(&self.transactions);
    }

    /// Set the transactions and re-derive the order commitment.
    pub fn with_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self.recompute_order_commitment();
        self
    }

    /// Set the cross-shard outbound messages.
    pub fn with_cross_shard_out(mut self, messages: Vec<CrossShardMessage>) -> Self {
        self.cross_shard_out = messages;
        self
    }

    /// Set the block timestamp (seconds).
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the declared proposer (the validator public key that signed it).
    pub fn with_proposer(mut self, proposer: [u8; 32]) -> Self {
        self.proposer = proposer;
        self
    }

    /// Set the published shard-head commitments (a masterchain block only).
    pub fn with_shard_headers(mut self, headers: Vec<ShardHeaderCommitment>) -> Self {
        self.shard_headers = headers;
        self
    }

    /// Set the attached precommit quorum certificate.
    pub fn with_precommit_qc(mut self, qc: Option<crate::consensus::QuorumCertificate>) -> Self {
        self.precommit_qc = qc;
        self
    }

    /// Set the committed epoch-MMR root (a masterchain epoch-boundary block
    /// only; see [`crate::mmr::commits_epoch_root`]).
    pub fn with_epoch_mmr_root(mut self, root: [u8; 32]) -> Self {
        self.mmr_epoch_root = root;
        self
    }

    /// The canonical block hash.
    ///
    /// CHAIN BINDING: the preimage starts with the domain tag, then the CHAIN
    /// ID ([`crate::consensus::consensus_chain_id`]), then the block fields.
    /// A block signed on one deployment therefore has a different hash — and a
    /// different signature — than the same block on another, so a testnet
    /// block (or a block signed by a testnet validator key) can never be
    /// replayed on mainnet. The domain tag was bumped `V2 -> V3` because the
    /// preimage layout changed.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Domain separator: version the block-commitment scheme.
        hasher.update(b"STELLEREUM_BLOCK_V3");
        // Chain id: binds the block (and every signature over its hash) to
        // THIS deployment. Without it a block is replayable across chains.
        hasher.update(crate::consensus::consensus_chain_id().to_be_bytes());
        hasher.update(self.shard_id.to_be_bytes());
        hasher.update(self.height.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.state_root);
        // CRITICAL: commit to EVERY transaction field (nonce, gas_limit, shards
        // and especially the SVM payload) via the full tx hash. Hashing only
        // from/to/amount let a proposer equivocate with two distinct bodies under
        // a single voted block hash, which would diverge node state after
        // finality. Signatures are intentionally excluded (they sign this hash).
        hasher.update((self.transactions.len() as u32).to_be_bytes());
        if !self.transactions.is_empty() {
            let mut tx_batch = Transaction::batch_hasher();
            for tx in &self.transactions {
                hasher.update(tx_batch.hash_one(tx));
            }
        }
        // TRANSACTION-ORDER COMMITMENT: the order Merkle root over the
        // transaction list, in execution order. Because it is inside the
        // block hash, the BFT quorum signs the ORDERING: a proposer that
        // reorders the body after the votes changes the hash, and a
        // validator re-computes the root from the proposed body and refuses
        // a proposal that does not match (the root is also checked
        // explicitly, so the refusal does not depend on the hash alone).
        //
        // The root is mixed in ONLY when it is non-zero, which is what keeps
        // every pre-existing block hash byte-for-byte: a block persisted
        // before the field existed decodes with the all-zero root, and so
        // does a block with no transactions (there is no order to commit).
        if self.order_merkle_root != [0u8; 32] {
            hasher.update(ORDER_MERKLE_COMMITMENT_TAG);
            hasher.update(self.order_merkle_root);
        }
        // Commit to cross-shard outbound messages as well.
        hasher.update((self.cross_shard_out.len() as u32).to_be_bytes());
        for m in &self.cross_shard_out {
            hasher.update(m.msg_id);
        }
        // FULL-MESSAGE COMMITMENT (cross-shard integrity hardening): alongside
        // the `msg_id` list above, bind the full canonical bytes of every
        // carried message under a tag, so mutating ANY committed field
        // (amount, recipient, proof, roots, flags, phase) moves the block hash
        // even when the `msg_id` is left untouched.
        //
        // VERSION RULE (frozen core): the section is mixed in ONLY when
        // `cross_shard_out` is non-empty — exactly like the order, shard-head,
        // epoch-key, last-QC and MMR commitments above. A block that carries
        // no cross-shard message therefore hashes byte-identically to before
        // this commitment existed (legacy chains keep their block hashes and
        // every signature over them keeps verifying); a block that carries
        // messages gets the stronger commitment.
        if !self.cross_shard_out.is_empty() {
            hasher.update(XSHARD_FULL_COMMITMENT_TAG);
            hasher.update((self.cross_shard_out.len() as u32).to_be_bytes());
            for m in &self.cross_shard_out {
                hasher.update(m.message_commitment());
            }
        }
        // SHARD-HEAD COMMITMENTS (TON `shard_hashes`): a masterchain block
        // commits to the latest finalized header of every workchain shard.
        // Because the commitment is mixed in ONLY for a non-empty set, a
        // block that publishes no shard head hashes exactly as it did before
        // the field existed — legacy chains keep their block hashes
        // byte-for-byte. A non-empty set is length-prefixed and
        // domain-separated, so it can never be confused with any other part
        // of the preimage.
        if !self.shard_headers.is_empty() {
            hasher.update(SHARD_HEADERS_COMMITMENT_TAG);
            hasher.update((self.shard_headers.len() as u32).to_be_bytes());
            for h in &self.shard_headers {
                hasher.update(h.commitment_bytes());
            }
        }
        // EPOCH-KEY COMMITMENT: the commitment to the MEV epoch key this
        // block's epoch uses (see [`crate::mev_epoch`]). It is mixed in ONLY
        // when it is non-zero, exactly like the order commitment: a block
        // whose epoch has no key (no DKG completed) and every block that
        // predates the field keep their pre-existing block hash byte-for-byte.
        if self.epoch_key_commitment != [0u8; 32] {
            hasher.update(EPOCH_KEY_COMMITMENT_TAG);
            hasher.update(self.epoch_key_commitment);
        }
        // CANONICAL DOWNTIME EVIDENCE (W10.5): the certificate that decided
        // height-1, embedded by the proposer. Mixed in ONLY when present, so
        // every block that predates canonical evidence keeps its pre-existing
        // block hash byte-for-byte. Signatures are hashed in canonical
        // (validator-id-sorted) order: the assembly order of a QC depends on
        // vote arrival timing and must not move the block hash.
        if let Some(qc) = &self.last_qc {
            hasher.update(LAST_QC_COMMITMENT_TAG);
            hasher.update(qc.height.to_be_bytes());
            hasher.update(qc.round.to_be_bytes());
            hasher.update([match qc.kind {
                crate::consensus::VoteKind::Prevote => 0u8,
                crate::consensus::VoteKind::Precommit => 1u8,
            }]);
            if let Some(bh) = &qc.block_hash {
                hasher.update([1u8]);
                hasher.update(bh);
            } else {
                hasher.update([0u8]);
            }
            let mut sigs = qc.signatures.clone();
            sigs.sort_by(|a, b| a.0.cmp(&b.0));
            hasher.update((sigs.len() as u32).to_be_bytes());
            for (voter, sig) in &sigs {
                hasher.update(voter);
                hasher.update((sig.len() as u32).to_be_bytes());
                hasher.update(sig);
            }
        }
        // EPOCH-MMR COMMITMENT (V5 Tier-2): the MMR root over the previous
        // epoch's finalized block hashes (see [`crate::mmr`]). Mixed in ONLY
        // when non-zero, exactly like the order and epoch-key commitments: a
        // block that predates the MMR and every block that is not an
        // epoch-committing boundary block keep their pre-existing block hash
        // byte-for-byte.
        if self.mmr_epoch_root != [0u8; 32] {
            hasher.update(MMR_EPOCH_COMMITMENT_TAG);
            hasher.update(self.mmr_epoch_root);
        }
        // CN-VRF v3 COMMITMENT: proposer reveal, epoch-ahead commits, and
        // optional epoch-boundary VDF beacon. Mixed in ONLY when `Some(...)`,
        // keeping every block with `cnvrf_v3: None` byte-identical to before.
        if let Some(payload) = &self.cnvrf_v3 {
            hasher.update(CNVRF_V3_COMMITMENT_TAG);
            hasher.update(payload.canonical_bytes());
        }
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.proposer);
        hasher.finalize().into()
    }

    /// The shard head this block commits to for `shard_id`, if any.
    pub fn shard_head(&self, shard_id: ShardId) -> Option<&ShardHeaderCommitment> {
        self.shard_headers.iter().find(|h| h.shard_id == shard_id)
    }

    /// True when the committed shard heads are in CANONICAL form: strictly
    /// ascending shard ids, no duplicates, and no entry for the masterchain
    /// itself (a block cannot commit to its own head).
    ///
    /// Canonical order matters because the set is hashed as a sequence: two
    /// byte orders of the same set would be two different block hashes, and a
    /// proposer could equivocate with them. Every honest builder sorts by
    /// shard id, and a validator refuses anything else.
    pub fn shard_headers_canonical(&self) -> bool {
        let mut last: Option<ShardId> = None;
        for h in &self.shard_headers {
            if h.shard_id == MASTERCHAIN_SHARD {
                return false;
            }
            if let Some(prev) = last {
                if h.shard_id <= prev {
                    return false;
                }
            }
            last = Some(h.shard_id);
        }
        true
    }

    /// Sign this block with a validator key.
    ///
    /// CHAIN BINDING: the signature covers the block HASH, and the block hash
    /// preimage carries the chain id (see [`Self::compute_hash`]). A signature
    /// produced on one deployment therefore never verifies on another, even
    /// with the same key.
    pub fn sign_block(&mut self, validator_key: &SigningKey) {
        let block_hash = self.compute_hash();
        let sig = validator_key.sign(&block_hash);
        self.validator_signatures
            .push((validator_key.verifying_key().to_bytes(), sig.to_vec()));
    }

    /// Sign this block with a validator Ed25519 key plus a Falcon-512 key.
    ///
    /// Mirrors EXACTLY what production `propose` does (`runtime.rs`: pushes
    /// `(ed_id, ed_sig)` then `(fk.validator_id(), fk.sign(hash))` over the
    /// single [`Self::compute_hash`] message — signatures are excluded from
    /// the hash, so one hash covers both halves), so that
    /// [`crate::consensus::verify_proposer_signature`] (Falcon-only,
    /// height-indexed) passes on the resulting block.
    ///
    /// The caller MUST register the Falcon public key for the proposer's Ed
    /// id first (via [`crate::consensus::register_validator_pq_key`); this
    /// helper does NOT register — mirroring the vote-fixture pattern where
    /// `Vote::sign_with_falcon` signs and the test registers separately.
    ///
    /// Deterministic in (block, keys) EXCEPT Falcon randomness:
    /// [`crate::post_quantum::FalconKeypair::sign`] mixes fresh OS entropy per signature (FIPS 206
    /// discrete Gaussian sampling), so two calls with the same inputs yield
    /// two DIFFERENT (both valid) Falcon halves, while the Ed25519 half is
    /// byte-identical.
    pub fn sign_block_with_falcon(
        &mut self,
        validator_key: &SigningKey,
        falcon_key: &FalconKeypair,
    ) {
        let block_hash = self.compute_hash();
        let ed_sig = validator_key.sign(&block_hash);
        self.validator_signatures
            .push((validator_key.verifying_key().to_bytes(), ed_sig.to_vec()));
        let falcon_sig = falcon_key.sign(&block_hash);
        self.validator_signatures
            .push((falcon_key.validator_id(), falcon_sig));
    }

    /// Verify the block carries a valid signature by its DECLARED proposer.
    ///
    /// SECURITY: proposal authenticity. Without this, any peer could broadcast a
    /// `Proposal` for another validator's slot (with valid transactions but no
    /// proposer signature) and have honest nodes prevote it — breaking
    /// attribution and letting an attacker inject proposals on someone's behalf.
    pub fn verify_proposer_signature(&self) -> bool {
        let hash = self.compute_hash();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            if *pubkey != self.proposer {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
                continue;
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            if vk.verify(&hash, &sig).is_ok() {
                return true;
            }
        }
        false
    }

    /// Verify the block carries a real validator quorum, by POWER.
    ///
    /// `verify_signatures(count)` counted distinct pubkeys with a valid signature
    /// and never checked whether any of them was a validator at all, so three
    /// throwaway keypairs satisfied it - a forged block history verified. The
    /// caller then made it worse by passing `quorum_power()`, a sum of stake
    /// units, where a head count was expected. Both halves had to change
    /// together: a signature is only evidence if it comes from a validator, and
    /// the threshold is a fraction of stake, not a number of names.
    ///
    /// A set with no power fails closed, because `quorum_power` is then
    /// unreachable.
    pub fn verify_validator_quorum(&self, validators: &crate::consensus::ValidatorSet) -> bool {
        let required = validators.quorum_power();
        if required == u64::MAX {
            return false;
        }
        let block_hash = self.compute_hash();
        // Dedup + membership first (cheap per item, input order preserved for a
        // deterministic fallback). The expensive crypto happens once below.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut candidates: Vec<(VerifyingKey, Signature, u64)> = Vec::new();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            // Count each validator at most once, or one key could sign N times to
            // fake an N-of-M quorum.
            if !seen.insert(*pubkey) {
                continue;
            }
            // Membership FIRST: an unknown key has no power and must not be
            // counted even if the signature is perfectly valid.
            let vp = validators.power_of(pubkey);
            if vp == 0 {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
                continue;
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            candidates.push((vk, sig, vp));
        }
        if candidates.is_empty() {
            return false;
        }
        // Fast path: one batch verification over the shared block hash.
        // Same-message batching; result is order-independent.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| block_hash.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s, _)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                let power: u64 = candidates.iter().map(|(_, _, p)| p).sum();
                return power >= required;
            }
        }
        // Slow path: batch rejected, so at least one signature is bad. Fall back
        // to per-signature checks in input order and count exactly the valid
        // power — one forged neighbor must not sink a good quorum, and a bad
        // quorum must not pass on its good members. Identical verdict to the
        // old scalar loop in all cases.
        let mut power = 0u64;
        for (vk, sig, vp) in &candidates {
            if vk.verify(&block_hash, sig).is_ok() {
                power = power.saturating_add(*vp);
            }
        }
        power >= required
    }

    /// Count distinct valid signers. Retained for tests and for code that has
    /// its own membership check; the consensus path must use
    /// `verify_validator_quorum`, which also weights by stake.
    pub fn verify_signatures(&self, required_quorum: usize) -> bool {
        // A zero quorum is nonsensical for consensus and must never accept a block.
        if required_quorum == 0 {
            return false;
        }
        let block_hash = self.compute_hash();
        // SECURITY: count each DISTINCT validator at most once. Otherwise a single
        // validator key signing the same block N times would fake an N-of-M quorum.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut valid = 0usize;

        // If `validator_signatures` carries a Falcon-512 signature for `self.proposer`
        // (under `self.proposer` or the derived PQ address), verify Falcon-512 via
        // `consensus::verify_proposer_signature` instead of relying solely on Ed25519.
        let proposer_pq_key = crate::consensus::pq_key_at_height(&self.proposer, self.height);
        let expected_pq_addr = proposer_pq_key.as_ref().map(|(scheme, pk)| {
            crate::post_quantum::derive_pq_address(*scheme, pk, &crate::post_quantum::DEFAULT_SALT)
        });
        let has_proposer_falcon = self
            .validator_signatures
            .iter()
            .any(|(signer_id, sig_bytes)| {
                sig_bytes.len() == crate::post_quantum::FALCON512_SIG_LEN
                    && (*signer_id == self.proposer
                        || expected_pq_addr
                            .as_ref()
                            .is_some_and(|addr| *signer_id == *addr))
            });
        if has_proposer_falcon {
            if !crate::consensus::verify_proposer_signature(self) {
                return false;
            }
            valid += 1;
            seen.insert(self.proposer);
            if let Some(addr) = expected_pq_addr {
                seen.insert(addr);
            }
            if valid >= required_quorum {
                return true;
            }
        }

        let mut candidates: Vec<(VerifyingKey, Signature)> = Vec::new();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            if !seen.insert(*pubkey) {
                continue; // duplicate signer -> ignore
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
                continue;
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            candidates.push((vk, sig));
        }
        if candidates.is_empty() {
            return valid >= required_quorum;
        }
        // Fast path: one batch verification over the shared block hash.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| block_hash.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                return valid + candidates.len() >= required_quorum;
            }
        }
        // Slow path: deterministic scalar fallback in input order — identical
        // verdict to the old per-signature loop.
        for (vk, sig) in &candidates {
            if vk.verify(&block_hash, sig).is_ok() {
                valid += 1;
            }
        }
        valid >= required_quorum
    }
}

/// Shared Sequencer for unified cross-shard ordering and external L2 rollup scheduling
#[derive(Clone, Debug, Default)]
pub struct SharedSequencer {
    pub current_sequence: u64,
    pub scheduled_cross_shard: Vec<(u64, CrossShardMessage)>,
    /// §5 M3: per-source sequenced-height watermark (see `assign_from_block`).
    /// Advanced ONLY from finalized block content — never by time/operator.
    pub watermark: std::collections::BTreeMap<ShardId, u64>,
}

impl SharedSequencer {
    pub fn new() -> Self {
        Self {
            current_sequence: 1,
            scheduled_cross_shard: Vec::new(),
            watermark: std::collections::BTreeMap::new(),
        }
    }

    pub fn sequence_message(&mut self, msg: CrossShardMessage) -> u64 {
        let seq = self.current_sequence;
        self.current_sequence += 1;
        self.scheduled_cross_shard.push((seq, msg));
        seq
    }
}

/// Shared Liquidity Hub across all shards providing atomic all-or-nothing execution
pub struct SharedLiquidityHub {
    pub active_shards: Vec<ShardId>,
    pub pending_inbound_cross_shard: HashMap<ShardId, Vec<CrossShardMessage>>,
    pub sequencer: SharedSequencer,
    /// Replay protection: msg_id of every message already routed/delivered.
    pub seen_cross_shard: std::collections::HashSet<[u8; 32]>,
}

impl SharedLiquidityHub {
    pub fn new(active_shards: Vec<ShardId>) -> Self {
        Self {
            active_shards,
            pending_inbound_cross_shard: HashMap::new(),
            sequencer: SharedSequencer::new(),
            seen_cross_shard: std::collections::HashSet::new(),
        }
    }

    /// Route cross-shard messages directly to destination shard with sequencer ordering.
    /// SECURITY:
    ///  - A message that fails inclusion verification is NEVER routed (bounced or dropped).
    ///  - Duplicate msg_id is rejected (cross-shard replay protection).
    pub fn route_cross_shard_message(&mut self, mut msg: CrossShardMessage) -> u64 {
        // Replay protection: reject an already-seen message id.
        if self.seen_cross_shard.contains(&msg.msg_id) {
            return 0;
        }

        // Unknown/inactive target shard: never queue into a phantom shard.
        // NOTE: a rejected message does NOT reserve its id — otherwise an invalid
        // message could block a later VALID one (e.g. a rejected untrusted copy of
        // a legitimate in-process message). Only accepted messages are marked seen.
        if !self.active_shards.contains(&msg.target_shard) {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                return self.sequencer.sequence_message(msg);
            }
            return 0;
        }

        // Routing-only check (Q-02): the `trusted` bypass inside
        // `verify_inclusion` is legitimate HERE (locally produced messages
        // carry it) but MUST NEVER reach credit — every apply path
        // re-verifies via strict/anchored/proof checks that ignore the flag.
        if !msg.verify_inclusion() {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                return self.sequencer.sequence_message(msg);
            }
            // Invalid and non-bounceable: drop, never route.
            return 0;
        }

        self.seen_cross_shard.insert(msg.msg_id);
        let target = msg.target_shard;
        let seq = self.sequencer.sequence_message(msg.clone());
        self.pending_inbound_cross_shard
            .entry(target)
            .or_default()
            .push(msg);
        seq
    }

    pub fn take_inbound_messages(&mut self, shard: ShardId) -> Vec<CrossShardMessage> {
        self.pending_inbound_cross_shard
            .remove(&shard)
            .unwrap_or_default()
    }

    /// Route a cross-shard message to its destination shard THROUGH a
    /// transport (the P2P gossip path or the node-local KV) instead of the
    /// in-process mailbox.
    ///
    /// Same admission rules as [`Self::route_cross_shard_message`] — replay
    /// protection, active-shard check, inclusion proof — but the admitted
    /// message is PUBLISHED to the transport instead of being queued in the
    /// process-local mailbox. With a P2P transport that is what carries the
    /// message to a shard running on ANOTHER host: the transport publishes it
    /// to the gossip topic of the target shard (see
    /// [`crate::network::cross_shard_topic`]).
    ///
    /// The message is NOT queued locally as well: the transport delivers it
    /// back to the destination shard, so queueing it here too would credit it
    /// twice.
    ///
    /// Returns the sequencer position of the routed message, or `0` when the
    /// message was rejected (replay, unknown target, failed inclusion). An
    /// `Err` means the transport refused the publish — the message was NOT
    /// marked as seen, so the caller may retry it.
    pub async fn route_cross_shard_message_via(
        &mut self,
        mut msg: CrossShardMessage,
        transport: &Arc<crate::network::CrossShardTransport>,
    ) -> Result<u64, String> {
        // Replay protection: an already-seen message id is never routed again.
        if self.seen_cross_shard.contains(&msg.msg_id) {
            return Ok(0);
        }

        // Unknown/inactive target shard: never route into a phantom shard —
        // bounce the message back to its source instead.
        if !self.active_shards.contains(&msg.target_shard) {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                transport.broadcast_cross_shard(&msg).await?;
                let seq = self.sequencer.sequence_message(msg);
                return Ok(seq);
            }
            return Ok(0);
        }

        // A message that fails the inclusion verification is NEVER routed.
        if !msg.verify_inclusion() {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                transport.broadcast_cross_shard(&msg).await?;
                let seq = self.sequencer.sequence_message(msg);
                return Ok(seq);
            }
            // Invalid and non-bounceable: drop, never route.
            return Ok(0);
        }

        transport.broadcast_cross_shard(&msg).await?;
        self.seen_cross_shard.insert(msg.msg_id);
        let seq = self.sequencer.sequence_message(msg);
        Ok(seq)
    }
}

impl SharedSequencer {
    /// Deterministically assign global sequence numbers to every cross-shard
    /// record in a FINALIZED block.
    ///
    /// ORDERING RULE (the M3 contract): records sort by
    /// `(block.height, msg.source_shard, msg.msg_id)` — source height first
    /// (causality across shards), then source shard (cross-shard tie-break),
    /// then message id (within-block tie-break). Each unseen
    /// [`CrossShardKey`] takes `next_sequence()` and the counter advances;
    /// already-sequenced keys keep their number (idempotent replay). Feed
    /// blocks in `(height, shard)` order and any two nodes derive identical
    /// assignments from identical chains. Returns the assignments in global
    /// order.
    pub fn assign_from_block(&mut self, block: &Block) -> Vec<(u64, CrossShardKey)> {
        let mut keys: Vec<CrossShardKey> = block
            .cross_shard_out
            .iter()
            .map(CrossShardKey::of)
            .collect();
        // Total order, independent of the carrier vec's order (KV enumeration
        // order must never leak into consensus-adjacent numbering).
        keys.sort_by(|a, b| {
            // `block.height` is common; order by (source_shard, msg_id, carrier).
            (a.source_shard, a.msg_id, a.finalized_in_block).cmp(&(
                b.source_shard,
                b.msg_id,
                b.finalized_in_block,
            ))
        });
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let seq = match self.sequence_of(&key) {
                Some(s) => s,
                None => {
                    let s = self.current_sequence;
                    self.current_sequence += 1;
                    // Keep the legacy schedule vector consistent (Sim reads it).
                    if let Some(msg) = block
                        .cross_shard_out
                        .iter()
                        .find(|m| CrossShardKey::of(m) == key)
                    {
                        self.scheduled_cross_shard.push((s, msg.clone()));
                    }
                    s
                }
            };
            out.push((seq, key));
        }
        // The watermark is finalized-block content only: the highest sequenced
        // source height per shard, advanced monotonically here.
        let wm = self.watermark.entry(block.shard_id).or_insert(0);
        if block.height > *wm {
            *wm = block.height;
        }
        out
    }

    /// The sequence number of an already-sequenced message, if any.
    pub fn sequence_of(&self, key: &CrossShardKey) -> Option<u64> {
        self.scheduled_cross_shard
            .iter()
            .find(|(_, m)| CrossShardKey::of(m) == *key)
            .map(|(s, _)| *s)
    }

    /// The next sequence number to be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.current_sequence
    }

    /// Highest sequenced source height per shard (the sequencer watermark).
    /// Advanced ONLY by [`Self::assign_from_block`] / [`Self::note_finalized`]
    /// on finalized blocks — never by time or by operator action.
    pub fn watermark(&self) -> &std::collections::BTreeMap<ShardId, u64> {
        &self.watermark
    }

    /// Advance the watermark for a finalized `(shard, height)` without
    /// assigning numbers (e.g. a finalized block with no cross-shard records).
    /// Monotonic: a stale height never moves it backwards.
    pub fn note_finalized(&mut self, source_shard: ShardId, height: u64) {
        let wm = self.watermark.entry(source_shard).or_insert(0);
        if height > *wm {
            *wm = height;
        }
    }
}
