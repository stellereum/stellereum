//! Compact block / vote propagation — DESIGN DOC + WIRED CODECS.
//!
//! # Status: WIRED (compact µQC + compact proposal paths, INACTIVE on the wire)
//!
//! Wired via `consensus_net.rs` (`#[path = "compact_prop.rs"] pub mod
//! compact_prop`, mirroring the `dandelion.rs` precedent). Two live-path
//! consumers exist, both gated on `COMPACT_GOSSIP_ACTIVATION_HEIGHT =
//! u64::MAX`:
//!
//! 1. the compact-µQC gossip frame (`encode_compact_qc` / `decode_compact_qc`);
//! 2. the COMPACT PROPOSAL path (`CompactProposal` / `BodyPull` / `Body`,
//!    receiver resolver `CompactResolver`): a block with hundreds of txs is
//!    announced as a header + 6-byte short ids instead of the full body.
//!
//! No node emits or accepts either frame until the lead flips the const.
//! Emission (`consensus_net::compact_proposal_from_block`), admission
//! (`ConsensusMsg::decode`) and the receiver entry point
//! (`consensus_net::open_compact_proposal`) all consult the same gate.
//!
//! # 1. Measured current wire sizes (bincode 1.3.3, = stellereum/Cargo.toml:20)
//!
//! Method: offline harness in /tmp (repo untouched) replicating the EXACT
//! field order/types below with bincode 1.3.3 and serializing. Struct
//! sources: `TransactionWire` (sharding.rs `TransactionWire`, `ShardId=u32` @:372),
//! `Vote`/`VoteKind` (`Vote`/`VoteKind` in consensus.rs), `QuorumCertificate`
//! (`QuorumCertificate` in consensus.rs), `ConsensusMsg` (`ConsensusMsg` in
//! consensus_net.rs), `Block` (`Block` in sharding.rs). Replicated substructures that are empty
//! in the measured case (payload, cross_shard_out, shard_headers, QCs)
//! contribute only their framing bytes, which is exact for those cases.
//!
//! ```text
//! tx plain (Ed25519 64 B sig, empty payload)      176 B  (= 96 fixed + 72 sigvec + 8 payloadvec)
//! tx priority-bid envelope (80 B sig)              192 B
//! vote bare, Some(hash)                            153 B  (= 8+4+4+33+32+72)
//! vote bare, nil                                     121 B
//! vote Falcon hybrid envelope (746 B sig)           835 B  (= 8+4+4+33+32+(8+746); sig field = 16 magic + 64 Ed + 666 Falcon per `FALCON512_SIG_LEN` (post_quantum.rs), consensus.rs:214 VOTE_FALCON_PART_LEN)
//! ConsensusMsg::Vote, locked=None (live path)       158 B
//! ConsensusMsg::Vote, locked=Some                    190 B
//! QC(k Ed25519 sigs, refused under pure PQ) = 57 + 104*k B  (k=1:161, 4:473, 7:785, 10:1097, 100:10457)
//! µQC Falcon envelope = 73 + ceil(C/8) + s*670 B  (s sigs; 670 = 4 len + 666 Falcon; layout `PqMicroCertificate` (consensus.rs), formula pinned by pq_qc_sizes_vs_classical; C=4 full-sign: 2754, QC bincode 2851)
//! block fixed part (0 txs, 1 proposer sig, no QCs)  350 B
//! ConsensusMsg::Proposal(N) = 366 + 176*N B (16 B msg framing + 350 B header)
//!   N=0:366  N=1:542  N=100:17966  N=428:75694  N=1000:176366
//! Committed{100 txs, qc7} (classical baseline)    18747 B
//! ```
//!
//! Encoding facts the table rests on (bincode 1.3, confirmed by harness):
//! fieldless enum (`VoteKind`, msg discriminant) = u32 LE = 4 B;
//! `Option<T>` tag = 1 B; `Vec` len prefix = u64 LE = 8 B; `[u8;32]` = 32 B
//! raw. E.g. vote = 8+4+4+33+32+(8+64) = 153. ✓
//!
//! # 2. Design
//!
//! ## 2a. Tx short-ids (mempool-synced set)
//! A compact proposal carries `Vec<[u8; 6]>` (`SHORT_ID_LEN = 6`, BIP152
//! width) instead of full transactions. `short_id = FNV-1a-64(salt || txid)`
//! truncated to 48 bits in the prototype; production MUST use
//! `BLAKE3("STELL_SHORTID_V1" || salt || txid)[..6]` — the KAT pins the
//! MECHANICS (derive/match/pack/size math), not the hash choice.
//! `salt = BLAKE3("STELL_COMPACT_SALT_V1" || height || prev_hash)` (see
//! [`salt_for_header`]): fixed before proposal, committed in the header
//! (`prev_hash` + `height`), so precomputation across heights is useless, and
//! the salt needs no extra wire bytes. Txs NOT admitted to the public mempool (sealed
//! MEV envelopes — mev_epoch.rs, private / priority-bid-carrying blobs a
//! receiver may lack) are ALWAYS sent full; short-ids name only
//! mempool-admitted txs. Receiver: look up each short-id in the local
//! mempool index; any miss/ambiguity → `BodyPull` request (see 2c).
//! Fail-closed: a short-id NEVER authorises execution — the block hash is
//! still computed over full txs, and a wrong/missing tx fails the hash.
//!
//! ## 2b. QC bitfield (read-only, no wire change yet)
//! Live reality: the counted path stays `signatures: Vec<(ValidatorId,
//! Vec<u8>)>` = 57 + 104*k B. The design ADDS (no removal, no wire change
//! yet) a canonical bitfield alongside the list:
//! `bitfield: Vec<u8>`, `bit i` (LSB-first) = signer index `i` in the
//! canonical validator order (sorted `ValidatorId`, same order as
//! `ValidatorSet::proposer_for`'s explicit sort).
//! Trailing unused bits MUST be zero (fail-closed unpack, mirroring the
//! existing µQC `signers_bitmask` rule and the PQ envelope bitlen check).
//! Uses NOW: downtime attribution and
//! evidence compare bitfields without re-walking sig lists; the verifier
//! keeps counting the Ed25519 list.
//!
//! ## 2c. Header-first + body-pull protocol (WIRED, activation-gated)
//! Precedent (read-only): `network.rs:541-590` already splits announcement
//! (DHT KV hash) from body (`fetch_blob` by hash), and `consensus_net`
//! gossips `Proposal` fire-and-forget under `MAX_BATCH_ITEMS=32` /
//! `MAX_BATCH_BYTES=512 KiB` / `MAX_CONSENSUS_MSG=32 MiB`
//! (consensus_net.rs:71-88). Implemented as the three gated
//! `ConsensusMsg` variants:
//!  1. Proposer gossips `CompactProposal{height, round, header(350 B),
//!     short_ids}` (`ConsensusMsg::CompactProposal`).
//!  2. Receiver resolves locally (`ShortIdIndex`); missing/ambiguous ids →
//!     bounded `BodyPull{block_hash, ids}` to the proposer/peers (cap
//!     [`COMPACT_PULL_MAX_IDS`] = 64 ids per request,
//!     [`COMPACT_PULL_MAX_ATTEMPTS`] = 3 attempts, then fall back to the
//!     full-proposal fetch).
//!  3. Proposer serves `Body{txs}` (`ConsensusMsg::Body`; full txs only for
//!     the requested ids, each bound to its id).
//!  4. Only a fully-resolved body whose hash matches the announcement enters
//!     prevote (`CompactResolver::complete`). `Committed` keeps carrying the
//!     full block + QC (catch-up path, rare — 18747 B @100tx/qc7).
//! Existing compact-ish mechanisms (read-only, no change): gossip `Batch`
//! amortization (P3-H4), proposer-side exact-size trim under
//! `MAX_CONSENSUS_MSG` (runtime.rs:4430-4449), `estimate_tx_wire_bytes`
//! packing heuristic (mempool.rs `estimate_tx_wire_bytes`), µQC bitmask certs
//! (`PqMicroCertificate::signers_bitmask` in consensus.rs), thin-proposal outbox dedup (main.rs:1320-1335).
//!
//! # 3. Projected savings (arithmetic from §1 measurements)
//!
//! ```text
//! CompactProposal(N, miss m) = 366 + 6*N + m*N*176 B
//!   N=100,  m=0%:    966 B  (-94.6% vs 17966)
//!   N=428,  m=0%:   2934 B  (-96.1% vs 75694)
//!   N=1000, m=0%:   6366 B  (-96.4% vs 176366)
//!   N=100,  m=5%:   1846 B  (-89.7%)
//!   N=428,  m=5%:   6700 B  (-91.1%)
//!   N=1000, m=5%:  15166 B  (-91.4%)
//! QC bitfield hybrid: +ceil(C/8)+1 B overhead NOW (C=100: +14 B)
//! ```
//! Votes are untouched by this design (158 B live path stays).
//!
//! # 4. Risks
//! * Mempool-sync assumption: projected savings assume receivers hold the
//!   txs. Sealed/private txs bypass short-ids (always full). A byzantine
//!   proposer can inflate miss rate → body-pull amplification; mitigations:
//!   per-request id caps, attempt bounds, peer down-scoring, and the hard
//!   `MAX_CONSENSUS_MSG` ceiling still applies to every frame.
//! * DoS surface of short-ids: 48-bit ids collide (birthday @1000 txs ≈
//!   9e-10/block, negligible) and an attacker can grind txs that collide
//!   with victim mempool entries (2^48 for a targeted hit — infeasible —
//!   but cheap near-miss spam pollutes indexes). Mitigations: per-height
//!   salt (`salt_for_header` over height + `prev_hash`), collision ⇒ treat
//!   as miss (`ShortIdIndex`), never mis-execute, mempool admission fees
//!   make grinding cost real, short-id index lookups O(1) and bounded.
//! * Wire change: the three variants are APPENDED after `Batch` (bincode
//!   indices 4/5/6) and refused by `ConsensusMsg::decode` while
//!   `COMPACT_GOSSIP_ACTIVATION_HEIGHT` is `u64::MAX`; `AGENTS.md` §7 still
//!   requires a spec update + audit note before the lead flips the const.

use crate::sharding::{Block, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Short-id width in bytes (BIP152 width). 48 bits: birthday collision
/// @1000 txs ≈ 5e5/2^49 ≈ 9e-10 per block — negligible; targeted preimage
/// needs 2^48 trials and the per-height salt kills precomputation.
pub const SHORT_ID_LEN: usize = 6;

/// Mempool-sync miss-rate assumption used by the 5%-column projections.
pub const ASSUMED_MISS_RATE_PCT: usize = 5;

/// Measured bincode-1.3 constants (see module doc §1 for method/sources).
pub const TX_PLAIN_BYTES: usize = 176;
pub const PROPOSAL_FIXED_BYTES: usize = 366;
pub const BLOCK_FIXED_BYTES: usize = 350;
pub const VOTE_MSG_BYTES: usize = 158;
pub const QC_FIXED_BYTES: usize = 57;
pub const QC_ED_SIG_ENTRY_BYTES: usize = 104; // 32 id + 8 len + 64 sig

/// Bincode-1.3 overhead of `Block::cnvrf_v3 == None` (1-byte `Option::None` tag).
pub const CNVRF_V3_ABSENT_OVERHEAD_BYTES: usize = 1;

/// Bincode-1.3 overhead of an active CN-VRF v3 proposer reveal (`Option<[u8; 48]>::Some`:
/// 1-byte `Option::Some` tag + 48-byte BLAKE3-XOF reverse hash-chain link).
pub const CNVRF_V3_REVEAL_OVERHEAD_BYTES: usize = 1 + 48;

/// Bincode-1.3 size of a reveal-only `Some(CnVrfV3BlockPayload)` trailing field
/// (`1` outer `Option::Some` + `49` `reveal` + `8` empty `commits` len + `1` `epoch_vdf: None`).
pub const CNVRF_V3_REVEAL_PAYLOAD_BYTES: usize = 1 + CNVRF_V3_REVEAL_OVERHEAD_BYTES + 8 + 1;

/// Derive a 6-byte short-id: domain-separated BLAKE3 over
/// `b"STELL_COMPACT_SHORT_ID_V1" || salt || txid`, truncated to
/// `SHORT_ID_LEN` bytes.
pub fn short_id(txid: &[u8; 32], salt: &[u8; 32]) -> [u8; SHORT_ID_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(b"STELL_COMPACT_SHORT_ID_V1");
    h.update(salt);
    h.update(txid);
    let digest = h.finalize();
    let mut out = [0u8; SHORT_ID_LEN];
    out.copy_from_slice(&digest.as_bytes()[..SHORT_ID_LEN]);
    out
}

/// Pack signer presence bits, LSB-first: validator index `i` (canonical
/// sorted order) sets bit `i % 8` of byte `i / 8`. Unused trailing bits are
/// always zero by construction.
pub fn pack_bitfield(signers: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; signers.len().div_ceil(8)];
    for (i, present) in signers.iter().enumerate() {
        if *present {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Unpack a bitfield; `None` on oversized `total` (`> COMPACT_QC_MAX_COMMITTEE * 16`),
/// length mismatch, OR any trailing unused bit set (fail-closed, mirrors the µQC
/// bitmask rule). All structural checks happen before allocating the output vector.
/// The round-trip `unpack(pack(x)) == Some(x)` holds for all bounded inputs.
pub fn unpack_bitfield(bits: &[u8], total: usize) -> Option<Vec<bool>> {
    if total > COMPACT_QC_MAX_COMMITTEE * 16 {
        return None;
    }
    if bits.len() != total.div_ceil(8) {
        return None;
    }
    // Trailing-bits-zero check before allocation: bits beyond `total` must be clear.
    let used_in_last = total % 8;
    if used_in_last != 0 {
        let mask = !((1u8 << used_in_last) - 1);
        if bits.last().is_some_and(|b| b & mask != 0) {
            return None;
        }
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        out.push(bits[i / 8] & (1 << (i % 8)) != 0);
    }
    Some(out)
}

/// Baseline `ConsensusMsg::Proposal` bytes for `n_txs` plain txs
/// (measured: 366 + 176*N).
pub fn baseline_proposal_bytes(n_txs: usize) -> usize {
    PROPOSAL_FIXED_BYTES + n_txs * TX_PLAIN_BYTES
}

/// Compact proposal bytes: header + 6 B/short-id + full bytes for misses.
///
/// Note: pre-CN-VRF-v3 baseline header (`PROPOSAL_FIXED_BYTES = 366` /
/// `BLOCK_FIXED_BYTES = 350`) excludes the trailing `Block::cnvrf_v3` field; use
/// [`compact_proposal_bytes_with_cnvrf_v3`] and [`cnvrf_v3_header_overhead_bytes`]
/// to account for the `1 B` absent tag or `49 B` reveal (`59 B` reveal-only payload).
pub fn compact_proposal_bytes(n_txs: usize, n_missing: usize) -> usize {
    PROPOSAL_FIXED_BYTES + n_txs * SHORT_ID_LEN + n_missing * TX_PLAIN_BYTES
}

/// Trailing CN-VRF v3 header overhead in bincode-1.3 bytes (excluding commits and epoch VDF):
/// - `has_payload == false` (`cnvrf_v3: None`): `1 B` (`CNVRF_V3_ABSENT_OVERHEAD_BYTES`)
/// - `has_payload == true, has_reveal == true`: `59 B` (`CNVRF_V3_REVEAL_PAYLOAD_BYTES`,
///   where `49 B` = `CNVRF_V3_REVEAL_OVERHEAD_BYTES` is `Option<[u8; 48]>`)
/// - `has_payload == true, has_reveal == false`: `11 B` (`1 + 1 + 8 + 1`)
pub const fn cnvrf_v3_header_overhead_bytes(has_payload: bool, has_reveal: bool) -> usize {
    if !has_payload {
        CNVRF_V3_ABSENT_OVERHEAD_BYTES
    } else if has_reveal {
        CNVRF_V3_REVEAL_PAYLOAD_BYTES
    } else {
        1 + 1 + 8 + 1
    }
}

/// Compact proposal bytes including the trailing CN-VRF v3 payload framing/reveal overhead
/// (assuming 0 commits and no epoch VDF beacon).
pub const fn compact_proposal_bytes_with_cnvrf_v3(
    n_txs: usize,
    n_missing: usize,
    has_reveal: bool,
) -> usize {
    PROPOSAL_FIXED_BYTES
        + n_txs * SHORT_ID_LEN
        + n_missing * TX_PLAIN_BYTES
        + cnvrf_v3_header_overhead_bytes(has_reveal, has_reveal)
}

/// Classical-baseline QC bytes for `n_sigs` Ed25519 signatures (refused under
/// pure PQ; live path is the Falcon µQC envelope, see §1): 57 + 104*k.
pub fn qc_bytes_ed(n_sigs: usize) -> usize {
    QC_FIXED_BYTES + n_sigs * QC_ED_SIG_ENTRY_BYTES
}

// ---------------------------------------------------------------------------
// Compact PROPOSAL gossip (LIVE-PATH WIRING — activation-gated, see header).
//
// The proposer announces `CompactProposal { header, block_hash, short_ids }`:
// the FULL block header (every field except `transactions`) plus one 6-byte
// short id per body slot, in block order. A receiver resolves the ids against
// its local mempool; misses are requested with a bounded `BodyPull` and
// answered by `Body`. Only a FULLY resolved body whose `compute_hash()`
// equals the announced `block_hash` is ever handed to prevote — a short id
// NEVER authorises execution, it only saves bytes.
//
// Non-mempool txs (sealed MEV envelopes, private blobs a peer cannot have)
// travel FULL inline in `full_txs`, index-anchored so the reconstructed body
// keeps the exact announced order.
// ---------------------------------------------------------------------------

/// Largest number of body slots one compact proposal may name.
///
/// Mirrors `MAX_BLOCK_TXS` (`runtime/mod.rs:47`, 10_000) with a citation
/// instead of an import: `consensus_net` is a lower-level module than
/// `runtime`, and a proposal naming more slots than a block the runtime would
/// build is invalid by construction. Bounds every per-proposal allocation.
pub const COMPACT_MAX_IDS: usize = 10_000;

/// Largest number of slots that may travel FULL inside one compact proposal
/// (sealed/private txs, which peers cannot resolve by short id).
///
/// A proposal that needs more inline bodies than this is not worth
/// compressing: the sender keeps the plain `Proposal` instead.
pub const COMPACT_MAX_FULL_SLOTS: usize = 1_024;

/// Hard byte ceiling of a compact proposal / pull / body frame.
///
/// Mirrors `MAX_CONSENSUS_MSG` (`consensus_net.rs:75`, 32 MiB): a compact
/// frame is still a gossip frame, so the infnode 32 MiB frame cap applies
/// unchanged. Enforced again by `ConsensusMsg::decode`; checked here so a
/// caller that only holds the payload type still refuses an over-cap frame
/// before allocating a body.
pub const COMPACT_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Max short ids one `BodyPull` may ask for (design §2c: "cap: e.g. 64 ids
/// per request"). One pull is one bounded amount of work for the responder.
pub const COMPACT_PULL_MAX_IDS: usize = 64;

/// Max pull attempts before the receiver gives up and fetches the FULL
/// proposal through the existing path (design §2c: "3 attempts").
pub const COMPACT_PULL_MAX_ATTEMPTS: u32 = 3;

/// Max bytes of one `Body` response. Same hard ceiling as every consensus
/// frame; [`COMPACT_PULL_MAX_IDS`] already keeps an honest response near
/// 64 × tx size, so the ceiling only ever catches abuse.
pub const COMPACT_PULL_MAX_RESPONSE_BYTES: usize = COMPACT_MAX_BYTES;

/// Per-height/per-branch short-id salt: `BLAKE3("STELL_COMPACT_SALT_V1" ||
/// height_le || prev_hash)`.
///
/// Derived from values the header already carries, so it costs NO wire bytes
/// on either side, while binding a short id to exactly one `(height,
/// prev_hash)` pair: an id precomputed (or ground) for another height or
/// branch never resolves here. `prev_hash` alone would already separate
/// heights on a single chain; mixing `height` in keeps the salt distinct even
/// at a genesis where `prev_hash` is all zero.
pub fn salt_for_header(header: &Block) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"STELL_COMPACT_SALT_V1");
    h.update(&header.height.to_le_bytes());
    h.update(&header.prev_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Why a compact-proposal frame or receiver action was refused.
///
/// Every variant is a FAIL-CLOSED answer: the caller drops the frame or falls
/// back to the full proposal, and never prevotes on a partially resolved body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactRefusal {
    /// The announced header still carries a body; a compact header MUST be
    /// bodyless (the body is exactly what the short ids name).
    HeaderNotBodyless,
    /// `CompactProposal::height` disagrees with `header.height` (the header is
    /// the signed object; the duplicate field is only a routing convenience).
    HeightMismatch,
    /// More body slots than [`COMPACT_MAX_IDS`].
    TooManyIds { ids: usize, max: usize },
    /// More inline bodies than [`COMPACT_MAX_FULL_SLOTS`].
    TooManyFullSlots { slots: usize, max: usize },
    /// An inline body names a slot outside `short_ids`.
    FullSlotOutOfRange(u32),
    /// Inline slots are not strictly increasing (duplicate or unsorted).
    FullSlotsUnsorted,
    /// An inline body does not hash to the short id announced for its slot.
    FullSlotIdMismatch(u32),
    /// Frame larger than [`COMPACT_MAX_BYTES`].
    FrameTooLarge { bytes: usize, max: usize },
    /// The local short-id index was built for a different salt (programming
    /// error at the call site; treated as a refusal, never as a miss).
    IndexSaltMismatch,
    /// One body slot could not be resolved (internal consistency guard).
    UnresolvedId([u8; SHORT_ID_LEN]),
    /// The resolved body's order commitment does not match the announced
    /// header (the header committed to a different ordering).
    OrderCommitmentMismatch,
    /// The resolved body does not hash to the announced `block_hash`.
    BlockHashMismatch,
    /// A pull with no ids.
    PullEmpty,
    /// A pull asking for more than [`COMPACT_PULL_MAX_IDS`].
    PullTooManyIds { ids: usize, max: usize },
    /// A pull naming the same id twice.
    PullDuplicateId([u8; SHORT_ID_LEN]),
    /// `attempt` must be in `1..=COMPACT_PULL_MAX_ATTEMPTS`.
    PullAttemptOutOfRange(u32),
    /// A body with no transactions.
    BodyEmpty,
    /// A body carrying more transactions than one pull may ask for.
    BodyTooManyTxs { txs: usize, max: usize },
    /// A body naming the same id twice (duplicate answer).
    BodyDuplicateId([u8; SHORT_ID_LEN]),
    /// A body entry whose tx does not hash to the id it claims.
    BodyIdMismatch([u8; SHORT_ID_LEN]),
    /// A body entry for an id the proposal did not name, or one already
    /// resolved (replay/duplicate).
    BodyUnknownId([u8; SHORT_ID_LEN]),
    /// A body answering a different `(height, round, block_hash)`.
    BodyWrongProposal,
    /// A body larger than [`COMPACT_PULL_MAX_RESPONSE_BYTES`].
    BodyResponseTooLarge { bytes: usize, max: usize },
}

impl std::fmt::Display for CompactRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderNotBodyless => write!(f, "compact header still carries a body"),
            Self::HeightMismatch => write!(f, "compact header height mismatch"),
            Self::TooManyIds { ids, max } => write!(f, "too many short ids: {ids} > {max}"),
            Self::TooManyFullSlots { slots, max } => {
                write!(f, "too many inline bodies: {slots} > {max}")
            }
            Self::FullSlotOutOfRange(idx) => write!(f, "inline body slot {idx} out of range"),
            Self::FullSlotsUnsorted => write!(f, "inline body slots not strictly increasing"),
            Self::FullSlotIdMismatch(idx) => write!(f, "inline body {idx} does not match its id"),
            Self::FrameTooLarge { bytes, max } => {
                write!(f, "compact frame too large: {bytes} > {max} bytes")
            }
            Self::IndexSaltMismatch => write!(f, "short-id index salt mismatch"),
            Self::UnresolvedId(id) => write!(f, "unresolved short id {}", hex::encode(id)),
            Self::OrderCommitmentMismatch => write!(f, "resolved body order commitment mismatch"),
            Self::BlockHashMismatch => write!(f, "resolved body hash != announced block hash"),
            Self::PullEmpty => write!(f, "empty body pull"),
            Self::PullTooManyIds { ids, max } => write!(f, "body pull too many ids: {ids} > {max}"),
            Self::PullDuplicateId(id) => write!(f, "body pull duplicate id {}", hex::encode(id)),
            Self::PullAttemptOutOfRange(attempt) => {
                write!(f, "body pull attempt {attempt} out of range")
            }
            Self::BodyEmpty => write!(f, "empty compact body"),
            Self::BodyTooManyTxs { txs, max } => {
                write!(f, "compact body too many txs: {txs} > {max}")
            }
            Self::BodyDuplicateId(id) => write!(f, "compact body duplicate id {}", hex::encode(id)),
            Self::BodyIdMismatch(id) => {
                write!(f, "compact body tx does not match id {}", hex::encode(id))
            }
            Self::BodyUnknownId(id) => {
                write!(f, "compact body id not requested {}", hex::encode(id))
            }
            Self::BodyWrongProposal => write!(f, "compact body answers a different proposal"),
            Self::BodyResponseTooLarge { bytes, max } => {
                write!(f, "compact body too large: {bytes} > {max} bytes")
            }
        }
    }
}

impl std::error::Error for CompactRefusal {}

/// One proposal body slot that could not be resolved locally.
///
/// Bounded request (design §2c step 2): never more than
/// [`COMPACT_PULL_MAX_IDS`] ids, never more than
/// [`COMPACT_PULL_MAX_ATTEMPTS`] attempts, and `attempt` is 1-based so the
/// responder can attribute repeats.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyPull {
    pub height: u64,
    pub round: u32,
    /// The proposal being completed (also the pull's correlation key).
    pub block_hash: [u8; 32],
    /// Missing short ids, in block order, unique.
    pub ids: Vec<[u8; SHORT_ID_LEN]>,
    /// 1-based attempt counter; anything outside `1..=MAX` refuses.
    pub attempt: u32,
}

impl BodyPull {
    /// Structural, fail-closed validation (bounded ids, no duplicates,
    /// bounded attempt, byte ceiling).
    pub fn validate(&self) -> Result<(), CompactRefusal> {
        if self.ids.is_empty() {
            return Err(CompactRefusal::PullEmpty);
        }
        if self.ids.len() > COMPACT_PULL_MAX_IDS {
            return Err(CompactRefusal::PullTooManyIds {
                ids: self.ids.len(),
                max: COMPACT_PULL_MAX_IDS,
            });
        }
        if self.attempt == 0 || self.attempt > COMPACT_PULL_MAX_ATTEMPTS {
            return Err(CompactRefusal::PullAttemptOutOfRange(self.attempt));
        }
        let mut seen = HashSet::with_capacity(self.ids.len());
        for id in &self.ids {
            if !seen.insert(*id) {
                return Err(CompactRefusal::PullDuplicateId(*id));
            }
        }
        let bytes = bincode::serialized_size(self).unwrap_or(u64::MAX);
        if bytes > COMPACT_MAX_BYTES as u64 {
            return Err(CompactRefusal::FrameTooLarge {
                bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
                max: COMPACT_MAX_BYTES,
            });
        }
        Ok(())
    }
}

/// Response to one [`BodyPull`]: the requested transactions, each BOUND to the
/// id it answers.
///
/// The id is repeated on the wire (6 B/tx) instead of relying on request
/// order: the receiver re-derives `short_id(txid, salt)` for every entry, so a
/// byzantine responder can never slip a DIFFERENT transaction into a slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Body {
    pub height: u64,
    pub round: u32,
    pub block_hash: [u8; 32],
    /// `(short id, transaction)` pairs, unique by id.
    pub txs: Vec<([u8; SHORT_ID_LEN], Transaction)>,
}

impl Body {
    /// Salt-independent structural checks (usable at decode time, before the
    /// answering proposal — and therefore the salt — is known).
    pub fn validate_structure(&self) -> Result<(), CompactRefusal> {
        if self.txs.is_empty() {
            return Err(CompactRefusal::BodyEmpty);
        }
        if self.txs.len() > COMPACT_PULL_MAX_IDS {
            return Err(CompactRefusal::BodyTooManyTxs {
                txs: self.txs.len(),
                max: COMPACT_PULL_MAX_IDS,
            });
        }
        let mut seen = HashSet::with_capacity(self.txs.len());
        for (id, _tx) in &self.txs {
            if !seen.insert(*id) {
                return Err(CompactRefusal::BodyDuplicateId(*id));
            }
        }
        let bytes = bincode::serialized_size(self).unwrap_or(u64::MAX);
        if bytes > COMPACT_PULL_MAX_RESPONSE_BYTES as u64 {
            return Err(CompactRefusal::BodyResponseTooLarge {
                bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
                max: COMPACT_PULL_MAX_RESPONSE_BYTES,
            });
        }
        Ok(())
    }

    /// Structural checks PLUS the id↔tx binding under `salt`: every entry MUST
    /// hash to the id it claims. This is the rule that makes a body response
    /// unable to smuggle a different transaction into a resolved slot.
    pub fn validate(&self, salt: &[u8; 32]) -> Result<(), CompactRefusal> {
        self.validate_structure()?;
        for (id, tx) in &self.txs {
            if short_id(&tx.compute_tx_hash(), salt) != *id {
                return Err(CompactRefusal::BodyIdMismatch(*id));
            }
        }
        Ok(())
    }
}

/// The compact announcement: header + short ids (+ inline bodies for slots a
/// receiver cannot resolve, see [`CompactProposal::full_txs`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactProposal {
    pub height: u64,
    pub round: u32,
    /// The announced block header: the FULL block with `transactions` empty.
    /// Every other field (state root, prev hash, proposer, signatures,
    /// commitments) is the block's own, and the receiver rebuilds the body
    /// into THIS header, so the header is the signed object.
    pub header: Block,
    /// Hash of the FULL block (header + resolved body), fixed before proposal
    /// and signed by the proposer. The receiver REFUSES a body that does not
    /// hash to it.
    pub block_hash: [u8; 32],
    /// One short id per body slot, in block order.
    pub short_ids: Vec<[u8; SHORT_ID_LEN]>,
    /// Slots whose tx travels FULL (sealed/private, not in the public
    /// mempool), strictly increasing by slot index.
    pub full_txs: Vec<(u32, Transaction)>,
}

impl CompactProposal {
    /// Build the announcement for `block`, sending `full_slots` inline.
    ///
    /// `full_slots` are body indices the proposer knows peers cannot resolve
    /// (sealed MEV envelopes, private txs). Duplicates are collapsed; an
    /// out-of-range index, an over-cap id list or an over-cap frame is refused
    /// here (the caller then keeps the plain `Proposal`).
    pub fn for_block(
        block: &Block,
        round: u32,
        full_slots: &[u32],
    ) -> Result<Self, CompactRefusal> {
        let mut header = block.clone();
        header.transactions.clear();
        let salt = salt_for_header(&header);
        let short_ids: Vec<[u8; SHORT_ID_LEN]> = block
            .transactions
            .iter()
            .map(|tx| short_id(&tx.compute_tx_hash(), &salt))
            .collect();
        let mut slots = full_slots.to_vec();
        slots.sort_unstable();
        slots.dedup();
        let mut full_txs = Vec::with_capacity(slots.len());
        for idx in slots {
            let tx = block
                .transactions
                .get(idx as usize)
                .ok_or(CompactRefusal::FullSlotOutOfRange(idx))?;
            full_txs.push((idx, tx.clone()));
        }
        let proposal = Self {
            height: block.height,
            round,
            header,
            block_hash: block.compute_hash(),
            short_ids,
            full_txs,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    /// Fail-closed structural validation, including the hard byte ceiling.
    pub fn validate(&self) -> Result<(), CompactRefusal> {
        if !self.header.transactions.is_empty() {
            return Err(CompactRefusal::HeaderNotBodyless);
        }
        if self.height != self.header.height {
            return Err(CompactRefusal::HeightMismatch);
        }
        if self.short_ids.len() > COMPACT_MAX_IDS {
            return Err(CompactRefusal::TooManyIds {
                ids: self.short_ids.len(),
                max: COMPACT_MAX_IDS,
            });
        }
        if self.full_txs.len() > COMPACT_MAX_FULL_SLOTS {
            return Err(CompactRefusal::TooManyFullSlots {
                slots: self.full_txs.len(),
                max: COMPACT_MAX_FULL_SLOTS,
            });
        }
        let salt = salt_for_header(&self.header);
        let mut prev: Option<u32> = None;
        for (idx, tx) in &self.full_txs {
            if (*idx as usize) >= self.short_ids.len() {
                return Err(CompactRefusal::FullSlotOutOfRange(*idx));
            }
            if prev.is_some_and(|p| *idx <= p) {
                return Err(CompactRefusal::FullSlotsUnsorted);
            }
            prev = Some(*idx);
            // An inline slot MUST still hash to the id announced for its slot:
            // otherwise a proposer could hand out a body that the short-id
            // resolution path would never accept.
            if short_id(&tx.compute_tx_hash(), &salt) != self.short_ids[*idx as usize] {
                return Err(CompactRefusal::FullSlotIdMismatch(*idx));
            }
        }
        let bytes = bincode::serialized_size(self).unwrap_or(u64::MAX);
        if bytes > COMPACT_MAX_BYTES as u64 {
            return Err(CompactRefusal::FrameTooLarge {
                bytes: usize::try_from(bytes).unwrap_or(usize::MAX),
                max: COMPACT_MAX_BYTES,
            });
        }
        Ok(())
    }

    /// True when the proposer sent every slot `full` (no short id needed).
    pub fn is_fully_inline(&self) -> bool {
        self.full_txs.len() == self.short_ids.len()
    }
}

/// A local mempool view of the short ids for ONE salt.
///
/// Built once per received compact proposal from the txs this node actually
/// holds (`Mempool::all()` at the receiver call site). Lookup is O(1);
/// a COLLISION between two distinct txs is recorded as ambiguous and treated
/// as a MISS by [`Self::resolve`] — never as a guess, so a colliding id can
/// only cost a body pull, never a mis-execution.
#[derive(Clone, Debug, Default)]
pub struct ShortIdIndex {
    salt: [u8; 32],
    /// id → the unique tx hashing to it, or `None` when two or more distinct
    /// txs do (ambiguous ⇒ miss).
    entries: HashMap<[u8; SHORT_ID_LEN], Option<Transaction>>,
}

impl ShortIdIndex {
    /// Empty index for `salt`.
    pub fn new(salt: [u8; 32]) -> Self {
        Self {
            salt,
            entries: HashMap::new(),
        }
    }

    /// Index `txs` for `salt` (the proposal header's [`salt_for_header`]).
    pub fn from_txs(salt: [u8; 32], txs: impl IntoIterator<Item = Transaction>) -> Self {
        let mut index = Self::new(salt);
        for tx in txs {
            index.insert(tx);
        }
        index
    }

    /// Salt this index was built for.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Add one tx; a second DISTINCT tx under the same id poisons the entry to
    /// "ambiguous" (see type docs).
    pub fn insert(&mut self, tx: Transaction) {
        let id = short_id(&tx.compute_tx_hash(), &self.salt);
        self.insert_at(id, tx);
    }

    /// Test hook: install `tx` under an EXPLICIT id, bypassing derivation, so
    /// the collision rule ("collision ⇒ miss") is testable without grinding
    /// 2^24 transactions. No live path calls this (grep-proof: tests only).
    #[doc(hidden)]
    pub fn insert_with_id_for_tests(&mut self, id: [u8; SHORT_ID_LEN], tx: Transaction) {
        self.insert_at(id, tx);
    }

    fn insert_at(&mut self, id: [u8; SHORT_ID_LEN], tx: Transaction) {
        match self.entries.get_mut(&id) {
            None => {
                self.entries.insert(id, Some(tx));
            }
            Some(slot) => {
                let same = slot
                    .as_ref()
                    .is_some_and(|held| held.compute_tx_hash() == tx.compute_tx_hash());
                if !same {
                    *slot = None;
                }
            }
        }
    }

    /// Resolve one id: `Some(tx)` only when exactly one DISTINCT tx hashes to
    /// it. Ambiguous (colliding) ids resolve to `None`, i.e. a miss.
    pub fn resolve(&self, id: &[u8; SHORT_ID_LEN]) -> Option<&Transaction> {
        self.entries.get(id).and_then(Option::as_ref)
    }

    /// Number of ids this index knows (ambiguous entries included).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the index holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why a receiver stops compressing and asks for the FULL proposal instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackReason {
    /// More ids missing than one bounded pull may ask for (e.g. a cold
    /// mempool): pulling would be amplification, so fetch the full proposal.
    TooManyMissing { missing: usize },
    /// [`COMPACT_PULL_MAX_ATTEMPTS`] pulls already went unanswered.
    AttemptsExhausted,
}

/// Receiver decision for one compact proposal state.
#[derive(Clone, Debug)]
pub enum Resolution {
    /// Every slot resolved and the body hashes to the announced header: the
    /// ONLY value that may be handed to prevote. Boxed to keep the enum small
    /// (a `Block` is hundreds of bytes; every other arm is tiny).
    Complete(Box<Block>),
    /// Some ids are missing within budget: send this bounded pull.
    Pull(BodyPull),
    /// Resolution cannot proceed within budget: fetch the full proposal
    /// through the existing path (never prevote on a partial body).
    FullProposal(FallbackReason),
}

/// Receiver-side state machine for ONE compact proposal.
///
/// Safety invariants:
/// * [`Self::complete`] is the only way to obtain a `Block`, and it checks the
///   announced order commitment AND the announced block hash;
/// * bodies are accepted only for ids this proposal named, only while
///   unresolved, and only when `short_id(txid, salt)` matches (so a response
///   can never substitute a different tx);
/// * pulls are capped by [`COMPACT_PULL_MAX_IDS`] and
///   [`COMPACT_PULL_MAX_ATTEMPTS`], and the frame/response byte ceilings match
///   [`COMPACT_MAX_BYTES`] (`MAX_CONSENSUS_MSG`).
#[derive(Clone, Debug)]
pub struct CompactResolver {
    proposal: CompactProposal,
    salt: [u8; 32],
    resolved: HashMap<[u8; SHORT_ID_LEN], Transaction>,
    attempts: u32,
}

impl CompactResolver {
    /// Validate + open a resolver for `proposal` (structural bounds, inline
    /// bodies seeded as resolved).
    pub fn new(proposal: CompactProposal) -> Result<Self, CompactRefusal> {
        proposal.validate()?;
        let salt = salt_for_header(&proposal.header);
        let mut resolved = HashMap::with_capacity(proposal.full_txs.len());
        for (idx, tx) in &proposal.full_txs {
            resolved.insert(proposal.short_ids[*idx as usize], tx.clone());
        }
        Ok(Self {
            proposal,
            salt,
            resolved,
            attempts: 0,
        })
    }

    /// The announcement this resolver is completing.
    pub fn proposal(&self) -> &CompactProposal {
        &self.proposal
    }

    /// Salt every short id in this proposal is bound to.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Pull attempts already issued for this proposal.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Resolve every still-missing slot against `index`, then decide:
    /// complete (hash-verified), one bounded pull, or full-proposal fallback.
    pub fn resolve_against(&mut self, index: &ShortIdIndex) -> Result<Resolution, CompactRefusal> {
        if index.salt() != &self.salt {
            return Err(CompactRefusal::IndexSaltMismatch);
        }
        let mut missing: Vec<[u8; SHORT_ID_LEN]> = Vec::new();
        let mut missing_set: HashSet<[u8; SHORT_ID_LEN]> = HashSet::new();
        for id in &self.proposal.short_ids {
            if self.resolved.contains_key(id) {
                continue;
            }
            if let Some(tx) = index.resolve(id) {
                self.resolved.insert(*id, tx.clone());
            } else if missing_set.insert(*id) {
                missing.push(*id);
            }
        }
        if missing.is_empty() {
            return self.complete().map(|b| Resolution::Complete(Box::new(b)));
        }
        if missing.len() > COMPACT_PULL_MAX_IDS {
            return Ok(Resolution::FullProposal(FallbackReason::TooManyMissing {
                missing: missing.len(),
            }));
        }
        if self.attempts >= COMPACT_PULL_MAX_ATTEMPTS {
            return Ok(Resolution::FullProposal(FallbackReason::AttemptsExhausted));
        }
        self.attempts += 1;
        Ok(Resolution::Pull(BodyPull {
            height: self.proposal.height,
            round: self.proposal.round,
            block_hash: self.proposal.block_hash,
            ids: missing,
            attempt: self.attempts,
        }))
    }

    /// Accept a `Body` response and continue resolution.
    ///
    /// Fail-closed: a duplicate/mismatched entry, an id the proposal never
    /// named (or already resolved), or a body answering a different proposal
    /// refuses the WHOLE body.
    pub fn accept_body(
        &mut self,
        body: &Body,
        index: &ShortIdIndex,
    ) -> Result<Resolution, CompactRefusal> {
        body.validate(&self.salt)?;
        if body.height != self.proposal.height
            || body.round != self.proposal.round
            || body.block_hash != self.proposal.block_hash
        {
            return Err(CompactRefusal::BodyWrongProposal);
        }
        let needed: HashSet<[u8; SHORT_ID_LEN]> = self
            .proposal
            .short_ids
            .iter()
            .copied()
            .filter(|id| !self.resolved.contains_key(id))
            .collect();
        // Two passes: refuse the WHOLE body before mutating any slot, so a
        // body with one bad entry cannot leave a half-applied state.
        for (id, _tx) in &body.txs {
            if !needed.contains(id) {
                return Err(CompactRefusal::BodyUnknownId(*id));
            }
        }
        for (id, tx) in &body.txs {
            self.resolved.insert(*id, tx.clone());
        }
        self.resolve_against(index)
    }

    /// Rebuild the full body in announced slot order and verify it against the
    /// announced header. The ONLY path that yields a block for prevote.
    fn complete(&self) -> Result<Block, CompactRefusal> {
        let mut block = self.proposal.header.clone();
        block.transactions = Vec::with_capacity(self.proposal.short_ids.len());
        for id in &self.proposal.short_ids {
            let tx = self
                .resolved
                .get(id)
                .ok_or(CompactRefusal::UnresolvedId(*id))?;
            block.transactions.push(tx.clone());
        }
        // Belt-and-braces BEFORE the hash: name the failure precisely when the
        // header commits to a different body order.
        if crate::mev::compute_order_merkle_root(&block.transactions) != block.order_merkle_root {
            return Err(CompactRefusal::OrderCommitmentMismatch);
        }
        // The definitive check: short ids never authorise execution; the body
        // must be the announced block, byte for byte.
        if block.compute_hash() != self.proposal.block_hash {
            return Err(CompactRefusal::BlockHashMismatch);
        }
        Ok(block)
    }
}

// ---------------------------------------------------------------------------
// Compact µQC gossip envelope (FIRST WIRING — gated, see header).
//
// The live path gossips finality as `ConsensusMsg::Committed` carrying the
// full bincode `QuorumCertificate`: outer framing plus one 32-byte
// `ValidatorId` per signer. The compact frame carries the SAME certificate
// content bitfield-indexed instead: no per-signer ids, no outer struct
// framing. Verification is untouched — the receiver rebuilds the identical
// certificate and runs the unmodified `QuorumCertificate::verify`.
// ---------------------------------------------------------------------------

/// Wire magic of a compact-µQC gossip frame.
///
/// Distinct from every existing magic (`STELL_UQC_PQ_V5_` /
/// `STELL_QC_PQ_V5__` µQC envelopes, `PQ1`, `STDL` dandelion stem,
/// `MLKEM*`, `STX1/STD1/…` epoch seals): old software never emits this
/// prefix, and its bincode-only `ConsensusMsg::decode` fails closed on it
/// (unknown first bytes), so old nodes IGNORE the frame, never choke.
pub const COMPACT_QC_MAGIC: &[u8; 8] = b"STCMQC01";

/// Largest committee a compact frame may name.
///
/// Mirrors `MAX_COMMIT_CERT_SIGNERS` (`consensus.rs:194`): the bitmask and
/// the signature count are both bounded by it, so one frame can never pin a
/// decoder past what the verifier already accepts. This file stays `std`-only
/// (standalone `rustc --test`), hence the local mirror with citation instead
/// of an import.
pub const COMPACT_QC_MAX_COMMITTEE: usize = 4096;

/// Largest single signature a compact frame may carry.
///
/// New DoS bound (no live counterpart: the µQC envelope has no per-sig cap,
/// only the total-frame cap): Falcon-512 signatures are 666 B
/// (`FALCON512_SIG_LEN` in post_quantum.rs), so 2048 B admits the live
/// scheme with headroom while bounding per-sig allocation. Fail-closed:
/// larger sigs refuse the whole frame.
pub const COMPACT_QC_MAX_SIG_BYTES: usize = 2048;

/// Largest compact frame in bytes.
///
/// Mirrors `MAX_CONSENSUS_MSG` (`consensus_net.rs:71`): a gossip frame is
/// still a gossip frame, so the infnode 32 MiB frame cap applies unchanged.
/// Local mirror with citation (file stays `std`-only).
pub const COMPACT_QC_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Falcon-512 wire signature length in bytes (`FALCON512_SIG_LEN` in post_quantum.rs).
/// Cited here so the size projector below stays honest about the live
/// signature width without importing the crate.
pub const COMPACT_QC_SIG_LEN_FALCON: usize = 666;

/// Vote-kind tags on the compact wire: 0 = Prevote, 1 = Precommit.
/// Mirrors `vote_kind_tag` (consensus_net.rs); anything else refuses.
pub const COMPACT_QC_KIND_PREVOTE: u8 = 0;
pub const COMPACT_QC_KIND_PRECOMMIT: u8 = 1;

/// A quorum certificate in compact gossip form: bitfield-indexed signers,
/// signatures only (no per-signer `ValidatorId`s, no bincode struct framing).
///
/// Field-for-field the content of the live `PqMicroCertificate` plus the
/// outer `QuorumCertificate` routing fields (`kind`, `block_hash`) needed to
/// rebuild a verifiable certificate on receipt. Plain owned data, no crate
/// deps (file stays `std`-only); `consensus_net` maps to/from the live types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactQc {
    pub height: u64,
    pub round: u32,
    /// 0 = Prevote, 1 = Precommit (`COMPACT_QC_KIND_*`).
    pub kind_tag: u8,
    pub block_hash: Option<[u8; 32]>,
    /// Raw `PqScheme::id()` (`post_quantum.rs:161`): 1 = Ed25519, 2 =
    /// Falcon512, 4 = Hybrid. Opaque here; `consensus_net` resolves it.
    pub scheme_id: u8,
    pub committee_size: u32,
    pub sortition_parent: [u8; 32],
    /// `ceil(committee_size / 8)` bytes, LSB-first, trailing bits zero
    /// (same rule as the µQC `signers_bitmask`).
    pub bitfield: Vec<u8>,
    /// Exactly one entry per SET bit (compact leg only — no sparse/full
    /// legs; anything else refuses fail-closed).
    pub signatures: Vec<Vec<u8>>,
}

/// Projected compact-frame bytes for a committee of `committee_size` with
/// `n_sigs` signatures of `sig_len` bytes each.
///
/// Layout: `MAGIC(8) || height(8) || round(4) || kind(1) || hash_flag(1) ||`
/// `hash(0|32) || scheme(1) || committee(4) || parent(32) || bitmask_len(4) ||`
/// `bitmask(ceil(C/8)) || sig_count(4) || n * (len(4) + sig)`.
/// The size test pins this projector against measured `encode_compact_qc`
/// output, so drift in either breaks the build loudly.
pub fn compact_qc_bytes(
    committee_size: usize,
    n_sigs: usize,
    sig_len: usize,
    has_hash: bool,
) -> usize {
    8 + 8
        + 4
        + 1
        + 1
        + if has_hash { 32 } else { 0 }
        + 1
        + 4
        + 32
        + 4
        + committee_size.div_ceil(8)
        + 4
        + n_sigs * (4 + sig_len)
}

/// Encode a compact QC gossip frame (canonical layout, see
/// [`compact_qc_bytes`]).
///
/// Fail-closed at encode: non-canonical inputs (`kind_tag > 1`,
/// `committee_size == 0` or over [`COMPACT_QC_MAX_COMMITTEE`], bitfield
/// length mismatch, trailing bits set, `signatures.len()` != set-bit count,
/// empty/oversized sigs, over [`COMPACT_QC_MAX_BYTES`]) return `Err` instead
/// of emitting a frame the decoder (or a peer) would refuse.
pub fn encode_compact_qc(qc: &CompactQc) -> Result<Vec<u8>, String> {
    if qc.kind_tag != COMPACT_QC_KIND_PREVOTE && qc.kind_tag != COMPACT_QC_KIND_PRECOMMIT {
        return Err("compact qc: bad kind tag".to_string());
    }
    if qc.committee_size == 0 || qc.committee_size as usize > COMPACT_QC_MAX_COMMITTEE {
        return Err("compact qc: bad committee size".to_string());
    }
    // Bitfield MUST be canonical: exact length + trailing bits zero. Reuses
    // `unpack_bitfield` (prototype §2b rule) as the validator.
    let present = unpack_bitfield(&qc.bitfield, qc.committee_size as usize)
        .ok_or_else(|| "compact qc: bad bitfield (length or trailing bits)".to_string())?;
    let set_bits = present.iter().filter(|&&b| b).count();
    // Compact leg only: exactly one signature per set bit.
    if qc.signatures.len() != set_bits {
        return Err("compact qc: sig count != set-bit count".to_string());
    }
    for sig in &qc.signatures {
        if sig.is_empty() || sig.len() > COMPACT_QC_MAX_SIG_BYTES {
            return Err("compact qc: bad signature length".to_string());
        }
    }
    let mut out = Vec::with_capacity(
        compact_qc_bytes(
            qc.committee_size as usize,
            qc.signatures.len(),
            qc.signatures.iter().map(|s| s.len()).max().unwrap_or(0),
            qc.block_hash.is_some(),
        )
        .max(8),
    );
    out.extend_from_slice(COMPACT_QC_MAGIC);
    out.extend_from_slice(&qc.height.to_le_bytes());
    out.extend_from_slice(&qc.round.to_le_bytes());
    out.push(qc.kind_tag);
    match &qc.block_hash {
        Some(h) => {
            out.push(1);
            out.extend_from_slice(h);
        }
        None => out.push(0),
    }
    out.push(qc.scheme_id);
    out.extend_from_slice(&qc.committee_size.to_le_bytes());
    out.extend_from_slice(&qc.sortition_parent);
    out.extend_from_slice(&(qc.bitfield.len() as u32).to_le_bytes());
    out.extend_from_slice(&qc.bitfield);
    out.extend_from_slice(&(qc.signatures.len() as u32).to_le_bytes());
    for sig in &qc.signatures {
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
    }
    if out.len() > COMPACT_QC_MAX_BYTES {
        return Err("compact qc: frame too large".to_string());
    }
    Ok(out)
}

/// Decode a compact QC gossip frame. `None` on ANY malformed input
/// (fail-closed): short buffers, wrong magic, out-of-range kind/hash flags,
/// bad committee size, bitfield length mismatch, set trailing bits, sig
/// count != set-bit count, empty/oversized sigs, truncation, OR trailing
/// bytes past the last signature.
pub fn decode_compact_qc(bytes: &[u8]) -> Option<CompactQc> {
    if bytes.len() < COMPACT_QC_MAGIC.len() || &bytes[..8] != COMPACT_QC_MAGIC {
        return None;
    }
    if bytes.len() > COMPACT_QC_MAX_BYTES {
        return None;
    }
    let mut cursor = 8usize;
    let take = |cursor: &mut usize, n: usize| -> Option<&[u8]> {
        if bytes.len() < *cursor + n {
            return None;
        }
        let s = &bytes[*cursor..*cursor + n];
        *cursor += n;
        Some(s)
    };
    let height = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);
    let round = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?);
    let kind_tag = *take(&mut cursor, 1)?.first()?;
    if kind_tag != COMPACT_QC_KIND_PREVOTE && kind_tag != COMPACT_QC_KIND_PRECOMMIT {
        return None;
    }
    let hash_flag = *take(&mut cursor, 1)?.first()?;
    let block_hash = match hash_flag {
        0 => None,
        1 => {
            let s = take(&mut cursor, 32)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(s);
            Some(h)
        }
        _ => return None,
    };
    let scheme_id = *take(&mut cursor, 1)?.first()?;
    let committee_size = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?);
    if committee_size == 0 || committee_size as usize > COMPACT_QC_MAX_COMMITTEE {
        return None;
    }
    let sortition_parent: [u8; 32] = {
        let s = take(&mut cursor, 32)?;
        let mut p = [0u8; 32];
        p.copy_from_slice(s);
        p
    };
    let bitmask_len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
    if bitmask_len != (committee_size as usize).div_ceil(8) {
        return None;
    }
    let bitfield = take(&mut cursor, bitmask_len)?.to_vec();
    // Canonical-bitfield rule (prototype §2b, via the prototype's own fn):
    // exact length (checked above) + trailing unused bits zero.
    let present = unpack_bitfield(&bitfield, committee_size as usize)?;
    let set_bits = present.iter().filter(|&&b| b).count();
    let sig_count = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
    // Compact leg only (mirrors the strict half of the µQC `is_compact`
    // check): sig count MUST equal the set-bit count.
    if sig_count != set_bits || sig_count > COMPACT_QC_MAX_COMMITTEE {
        return None;
    }
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let sig_len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
        if sig_len == 0 || sig_len > COMPACT_QC_MAX_SIG_BYTES {
            return None;
        }
        signatures.push(take(&mut cursor, sig_len)?.to_vec());
    }
    // No trailing bytes (mirrors `ConsensusMsg::decode`'s
    // `reject_trailing_bytes`): padding must not ride along.
    if cursor != bytes.len() {
        return None;
    }
    Some(CompactQc {
        height,
        round,
        kind_tag,
        block_hash,
        scheme_id,
        committee_size,
        sortition_parent,
        bitfield,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kat_short_id_vectors() {
        // Independent cross-check against keyed/domain-separated BLAKE3:
        // BLAKE3(b"STELL_COMPACT_SHORT_ID_V1" || salt || txid)[..6].
        let txid = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let expected_salted = {
            let mut h = blake3::Hasher::new();
            h.update(b"STELL_COMPACT_SHORT_ID_V1");
            h.update(&salt);
            h.update(&txid);
            let mut buf = [0u8; SHORT_ID_LEN];
            buf.copy_from_slice(&h.finalize().as_bytes()[..SHORT_ID_LEN]);
            buf
        };
        assert_eq!(short_id(&txid, &salt), expected_salted);
        // Salt separation: same txid, zero salt differs.
        let zero = [0u8; 32];
        let expected_zero = {
            let mut h = blake3::Hasher::new();
            h.update(b"STELL_COMPACT_SHORT_ID_V1");
            h.update(&zero);
            h.update(&txid);
            let mut buf = [0u8; SHORT_ID_LEN];
            buf.copy_from_slice(&h.finalize().as_bytes()[..SHORT_ID_LEN]);
            buf
        };
        assert_eq!(short_id(&txid, &zero), expected_zero);
        assert_ne!(expected_salted, expected_zero);
        // Determinism + avalanche: one-bit txid flip changes the id.
        let mut txid2 = txid;
        txid2[0] ^= 1;
        let a = short_id(&txid, &salt);
        let b = short_id(&txid2, &salt);
        assert_eq!(a, short_id(&txid, &salt));
        assert_ne!(a, b);
        assert_eq!(a.len(), SHORT_ID_LEN);
    }

    #[test]
    fn kat_bitfield_pack_vectors() {
        // LSB-first packing, hand-verified: indices 0,2,8 set =>
        // byte0 = 0b00000101, byte1 = 0b00000001.
        let mut s = vec![false; 10];
        s[0] = true;
        s[2] = true;
        s[8] = true;
        assert_eq!(pack_bitfield(&s), vec![0x05, 0x01]);
        assert_eq!(pack_bitfield(&[]), Vec::<u8>::new());
        assert_eq!(pack_bitfield(&[false; 8]), vec![0x00]);
        assert_eq!(pack_bitfield(&[true; 8]), vec![0xff]);
        // 100-validator committee, first 7 sign => 13 bytes, byte0 = 0x7f.
        let mut c = vec![false; 100];
        for b in c.iter_mut().take(7) {
            *b = true;
        }
        let packed = pack_bitfield(&c);
        assert_eq!(packed.len(), 13);
        assert_eq!(packed[0], 0x7f);
        assert!(packed[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn kat_bitfield_unpack_round_trip_and_fail_closed() {
        let mut s = vec![false; 10];
        s[0] = true;
        s[2] = true;
        s[8] = true;
        assert_eq!(unpack_bitfield(&[0x05, 0x01], 10), Some(s));
        // Trailing bit set (bit 2 of byte 1 is index 10, out of range) => None.
        assert_eq!(unpack_bitfield(&[0x05, 0x05], 10), None);
        // Length mismatch => None.
        assert_eq!(unpack_bitfield(&[0x05], 10), None);
        assert_eq!(unpack_bitfield(&[0x05, 0x01, 0x00], 10), None);
        // Empty committee round-trips.
        assert_eq!(unpack_bitfield(&[], 0), Some(vec![]));
        // Oversized `total` fails closed before allocation (OOM guard).
        let over_cap = COMPACT_QC_MAX_COMMITTEE * 16 + 1;
        let over_bytes = vec![0u8; over_cap.div_ceil(8)];
        assert_eq!(unpack_bitfield(&over_bytes, over_cap), None);
        assert_eq!(unpack_bitfield(&[], usize::MAX), None);
    }

    #[test]
    fn kat_size_math_matches_measurements() {
        // Spot-checks against the §1 harness measurements.
        assert_eq!(baseline_proposal_bytes(0), 366);
        assert_eq!(baseline_proposal_bytes(100), 17966);
        assert_eq!(baseline_proposal_bytes(428), 75694);
        assert_eq!(baseline_proposal_bytes(1000), 176366);
        assert_eq!(qc_bytes_ed(1), 161);
        assert_eq!(qc_bytes_ed(7), 785);
        assert_eq!(qc_bytes_ed(100), 10457);
        // Projection columns (§3): m=0 and m=5%.
        assert_eq!(compact_proposal_bytes(100, 0), 966);
        assert_eq!(compact_proposal_bytes(428, 0), 2934);
        assert_eq!(compact_proposal_bytes(1000, 0), 6366);
        assert_eq!(compact_proposal_bytes(100, 5), 1846);
        assert_eq!(compact_proposal_bytes(1000, 50), 15166);
        // Savings are real and large: compact(1000,0) < 4% of baseline.
        assert!(compact_proposal_bytes(1000, 0) * 100 < baseline_proposal_bytes(1000) * 4);
    }

    #[test]
    fn cnvrf_v3_header_overhead_accounting() {
        assert_eq!(CNVRF_V3_ABSENT_OVERHEAD_BYTES, 1);
        assert_eq!(CNVRF_V3_REVEAL_OVERHEAD_BYTES, 49);
        assert_eq!(CNVRF_V3_REVEAL_PAYLOAD_BYTES, 59);
        assert_eq!(cnvrf_v3_header_overhead_bytes(false, false), 1);
        assert_eq!(cnvrf_v3_header_overhead_bytes(true, false), 11);
        assert_eq!(cnvrf_v3_header_overhead_bytes(true, true), 59);
        assert_eq!(
            compact_proposal_bytes_with_cnvrf_v3(100, 0, false),
            compact_proposal_bytes(100, 0) + 1
        );
        assert_eq!(
            compact_proposal_bytes_with_cnvrf_v3(100, 0, true),
            compact_proposal_bytes(100, 0) + 59
        );
    }

    /// Deterministic 64-seat compact-QC fixture (structural only — signature
    /// bytes are patterned filler, NOT crypto; verification stays in
    /// `QuorumCertificate::verify` and is never exercised here).
    fn fixture_64_seat(all_sign: bool) -> CompactQc {
        let mut signers = vec![false; 64];
        if all_sign {
            for b in signers.iter_mut() {
                *b = true;
            }
        } else {
            // Quorum of a uniform 64-seat committee: floor(2*64/3)+1 = 43.
            for b in signers.iter_mut().take(43) {
                *b = true;
            }
        }
        let n = signers.iter().filter(|&&b| b).count();
        CompactQc {
            height: 900,
            round: 3,
            kind_tag: COMPACT_QC_KIND_PRECOMMIT,
            block_hash: Some([0xABu8; 32]),
            scheme_id: 2, // Falcon512 (`post_quantum.rs:161`).
            committee_size: 64,
            sortition_parent: [0x77u8; 32],
            bitfield: pack_bitfield(&signers),
            signatures: (0..n)
                .map(|i| vec![(i as u8).wrapping_mul(7).wrapping_add(1); COMPACT_QC_SIG_LEN_FALCON])
                .collect(),
        }
    }

    #[test]
    fn compact_qc_round_trip() {
        for qc in [fixture_64_seat(true), fixture_64_seat(false)] {
            let bytes = encode_compact_qc(&qc).expect("fixture must encode");
            assert_eq!(
                bytes.len(),
                compact_qc_bytes(64, qc.signatures.len(), COMPACT_QC_SIG_LEN_FALCON, true),
                "projector must match measured bytes exactly"
            );
            let back = decode_compact_qc(&bytes).expect("must decode");
            assert_eq!(back, qc);
        }
        // Nil-hash (prevote) frame round-trips too.
        let mut nil = fixture_64_seat(false);
        nil.block_hash = None;
        nil.kind_tag = COMPACT_QC_KIND_PREVOTE;
        let bytes = encode_compact_qc(&nil).expect("nil frame must encode");
        assert_eq!(
            bytes.len(),
            compact_qc_bytes(64, 43, COMPACT_QC_SIG_LEN_FALCON, false)
        );
        assert_eq!(decode_compact_qc(&bytes).expect("must decode"), nil);
    }

    #[test]
    fn compact_qc_tamper_refusal() {
        let qc = fixture_64_seat(true);
        let good = encode_compact_qc(&qc).expect("fixture must encode");
        // Baseline sanity.
        assert!(decode_compact_qc(&good).is_some());
        // Wrong magic (old/new interop: no magic, no parse).
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(decode_compact_qc(&bad_magic), None);
        assert_eq!(decode_compact_qc(&[]), None);
        assert_eq!(decode_compact_qc(&good[..7]), None);
        // Every truncation refuses.
        for n in [8usize, 20, 60, 100, 1000] {
            assert_eq!(
                decode_compact_qc(&good[..n.min(good.len() - 1)]),
                None,
                "truncation to {n} must refuse"
            );
        }
        // Trailing byte refuses (no padding rides along).
        let mut padded = good.clone();
        padded.push(0x00);
        assert_eq!(decode_compact_qc(&padded), None);
        // Bad kind / hash flags refuse.
        let mut bad_kind = good.clone();
        bad_kind[8 + 8 + 4] = 2;
        assert_eq!(decode_compact_qc(&bad_kind), None);
        let mut bad_flag = good.clone();
        bad_flag[8 + 8 + 4 + 1] = 2;
        assert_eq!(decode_compact_qc(&bad_flag), None);
        // Trailing bit set in the bitfield refuses (64 seats: no spare bits,
        // so corrupt the length prefix instead: bitmask_len 8 -> 9).
        let bitlen_off = 8 + 8 + 4 + 1 + 1 + 32 + 1 + 4 + 32;
        let mut bad_len = good.clone();
        bad_len[bitlen_off] = 9;
        assert_eq!(decode_compact_qc(&bad_len), None);
        // Non-multiple-of-8 committee exercises the trailing-bit rule: build
        // a 10-seat frame, then set bit 10 (first out-of-range bit).
        let mut s10 = vec![false; 10];
        s10[0] = true;
        s10[9] = true;
        let qc10 = CompactQc {
            height: 1,
            round: 0,
            kind_tag: COMPACT_QC_KIND_PREVOTE,
            block_hash: None,
            scheme_id: 2,
            committee_size: 10,
            sortition_parent: [0u8; 32],
            bitfield: pack_bitfield(&s10),
            signatures: vec![vec![1u8; 64], vec![2u8; 64]],
        };
        let mut b10 = encode_compact_qc(&qc10).expect("10-seat must encode");
        // Bitfield starts after magic(8)+height(8)+round(4)+kind(1)+flag(1)+
        // scheme(1)+committee(4)+parent(32)+len(4) = 63; byte 1 bit 2 = index 10.
        b10[63 + 1] |= 1 << 2;
        assert_eq!(decode_compact_qc(&b10), None);
        // Sig count != set-bit count refuses.
        let mut qc_mismatch = qc.clone();
        qc_mismatch.signatures.pop();
        assert!(encode_compact_qc(&qc_mismatch).is_err());
        // Empty / oversized sigs refuse at encode.
        let mut qc_empty_sig = qc.clone();
        qc_empty_sig.signatures[0].clear();
        assert!(encode_compact_qc(&qc_empty_sig).is_err());
        let mut qc_big_sig = qc.clone();
        qc_big_sig.signatures[0] = vec![0u8; COMPACT_QC_MAX_SIG_BYTES + 1];
        assert!(encode_compact_qc(&qc_big_sig).is_err());
        // Bad committee sizes refuse at encode.
        let mut qc_zero = qc.clone();
        qc_zero.committee_size = 0;
        qc_zero.bitfield = vec![];
        qc_zero.signatures = vec![];
        assert!(encode_compact_qc(&qc_zero).is_err());
        let mut qc_huge = qc.clone();
        qc_huge.committee_size = COMPACT_QC_MAX_COMMITTEE as u32 + 1;
        assert!(encode_compact_qc(&qc_huge).is_err());
        let mut qc_kind = qc.clone();
        qc_kind.kind_tag = 7;
        assert!(encode_compact_qc(&qc_kind).is_err());
    }

    #[test]
    fn compact_qc_size_64_seat_savings() {
        // 64 seats, full-sign, Falcon-512 sigs, block hash present — the live
        // finality shape (µQC over the whole set).
        let qc = fixture_64_seat(true);
        let measured = encode_compact_qc(&qc).expect("fixture must encode").len();
        // Fixed overhead: 8+8+4+1+1+32+1+4+32+4+8+4 = 107; sigs 64*(4+666).
        assert_eq!(measured, 107 + 64 * (4 + COMPACT_QC_SIG_LEN_FALCON));
        assert_eq!(measured, 42987);
        assert_eq!(
            measured,
            compact_qc_bytes(64, 64, COMPACT_QC_SIG_LEN_FALCON, true)
        );
        // Quorum-sign (43 of 64) frame is smaller still.
        let q43 = fixture_64_seat(false);
        let m43 = encode_compact_qc(&q43).expect("must encode").len();
        assert_eq!(m43, 107 + 43 * (4 + COMPACT_QC_SIG_LEN_FALCON));
        assert_eq!(m43, 28917);
        assert!(m43 < measured);
    }
}
