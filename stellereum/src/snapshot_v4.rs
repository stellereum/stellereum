//! State Checkpoint v4 (`SnapV4`) — isolated, canonical, bounded codec and validator.
//!
//! Implements §2 of `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md`:
//! - `SnapshotManifestV1` with pre-allocation DoS caps (`MAX_SNAP_UNITS`,
//!   `MAX_SNAP_CHUNK_BYTES`, `MAX_SNAP_WIRE_BYTES`, `MAX_SNAPSHOT_DECODE_BYTES`,
//!   `MAX_DELTA_CHAIN_LEN = 8`), `units_merkle_root`, and domain-separated Falcon-512
//!   publisher signature verified against `(chain_id, shard, height,
//!   trusted_state_root, trusted_boundary_hash, validator_set)` BEFORE touching
//!   or allocating any unit payloads.
//! - `Base` mode: 256 deterministic prefix buckets (`addr[0] ∈ 0x00..=0xFF`,
//!   sorted by `address: [u8; 32]`, sub-chunked at `MAX_ACCOUNTS_PER_CHUNK` /
//!   `MAX_SNAP_CHUNK_BYTES`, empty buckets encoded as `UnchangedRef` with
//!   `BLAKE3("STELL_SNAP_BUCKET_EMPTY_V1")` and 0 wire bytes) plus 16 canonical
//!   `DomainUnitId` units (`Scalars` .. `EvmBindings`).
//! - `Delta` mode: `AccountBucketDelta` / `MapDiff` / `ScalarsDelta` /
//!   `CrossShardDelta` / `UnchangedRef`, with strict `base_state_root` and
//!   monotonic `base_height < target_height` chain verification, uniqueness and
//!   strict ordering checks on all buckets and keys, 70% full-unit fallback,
//!   checked arithmetic, and `reject_trailing_bytes` on every bincode decode.
//!
//! # Absolute Safety Isolation Invariant (`SafetyRecordStore`)
//!
//! By contract (`W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §0, §1.2, §2.6):
//! - `safety_record_v1` (`crate::storage::SafetyRecordStore`),
//! - `ConsensusCheckpoint` (`meta["consensus"]`), and
//! - `VoteWatermark` (`meta["vote_watermark"]`)
//!   are **STRICTLY EXCLUDED** from `SnapV4`. This module never reads, serializes,
//!   transmits, imports, overwrites, resets, or touches `safety_record_v1`,
//!   `ConsensusCheckpoint`, or `VoteWatermark` under any code path.

use bincode::Options;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::bridge::BridgeState;
use crate::consensus::{pq_key_at_height, ValidatorId, ValidatorSet};
use crate::contract::{Contract, ContractRegistry};
use crate::contract_abi::ContractAbi;
use crate::governance::{AppliedParams, Governance, Proposal, ProposalStatus, VoteChoice};
use crate::oracle::OracleState;
use crate::orderbook::{OrderbookActor, OrderbookManager};
use crate::pmm::PrimaryMarketMaker;
use crate::post_quantum::{verify_pq_signature, FalconKeypair, PqScheme, FALCON512_SIG_LEN};
use crate::sharding::{CrossShardKey, CrossShardReplaySnapshot, Transaction};
use crate::staking::{
    CommissionSchedule, JailRecord, StakingLedger, UnbondingEntry, ValidatorRewardState,
    ValidatorStake,
};
use crate::state_engine::{
    AccountState, CnVrfV3EngineSnapshot, EscrowRecord, EvmBindingsSnapshot, EvmBindingsState,
    InMemoryStateEngine, StateSnapshotV2,
};
use crate::storage::DomainSnapshot;
use crate::token::{TokenActor, TokenMetadata, TokenRegistry};
use crate::tokenomics::TeamVestingSchedule;
use crate::xshard2pc::XpcRecord;
use crate::zkml::{SessionKeyRegistry, ZkMlModelRegistry};

// ============================================================================
// Constants & Anti-DoS Bounds (§2.1, §2.2, §2.4)
// ============================================================================

/// Magic header of `SnapshotManifestV1` (`"STLSNPM1"`).
pub const SNAP_MANIFEST_MAGIC: [u8; 8] = *b"STLSNPM1";
/// Supported manifest format version.
pub const SNAP_MANIFEST_VERSION: u16 = 1;

/// Domain separator for Falcon-512 signature over `SnapshotManifestV1`.
pub const SNAP_MANIFEST_SIG_DOMAIN: &[u8] = b"STELL_SNAP_MANIFEST_V1\0";
/// Domain separator for unit content hashes.
pub const SNAP_UNIT_HASH_DOMAIN: &[u8] = b"STELL_SNAP_UNIT_V1\0";
/// Domain separator for empty account buckets (`W1` §2.1).
pub const SNAP_EMPTY_BUCKET_DOMAIN: &[u8] = b"STELL_SNAP_BUCKET_EMPTY_V1";
/// Domain separator for multi-chunk bucket aggregate hash.
pub const SNAP_BUCKET_MULTI_DOMAIN: &[u8] = b"STELL_SNAP_BUCKET_MULTI_V1\0";
/// Domain separator for multi-chunk domain aggregate hash.
pub const SNAP_DOMAIN_MULTI_DOMAIN: &[u8] = b"STELL_SNAP_DOMAIN_MULTI_V1\0";
/// Domain separator for canonical `ValidatorSet` hash.
pub const SNAP_VSET_HASH_DOMAIN: &[u8] = b"STELL_SNAP_VSET_V1\0";
/// Domain separators for `units_merkle_root`.
pub const SNAP_MERKLE_EMPTY_DOMAIN: &[u8] = b"STELL_SNAP_MERKLE_EMPTY_V1\0";
pub const SNAP_MERKLE_LEAF_DOMAIN: &[u8] = b"STELL_SNAP_MERKLE_LEAF_V1\0";
pub const SNAP_MERKLE_NODE_DOMAIN: &[u8] = b"STELL_SNAP_MERKLE_NODE_V1\0";

/// Number of prefix buckets for account partitioning (`addr[0] ∈ 0x00..=0xFF`).
pub const N_ACCOUNT_BUCKETS: usize = 256;
/// Maximum accounts per sub-chunk before splitting.
pub const MAX_ACCOUNTS_PER_CHUNK: usize = 16_384;
/// Hard cap on unit descriptors in a single `SnapshotManifestV1` (pre-allocation bound).
pub const MAX_SNAP_UNITS: usize = 4_096;
/// Hard cap on a single uncompressed wire chunk (1 MiB).
pub const MAX_SNAP_CHUNK_BYTES: usize = 1_048_576;
/// Hard cap on total wire bytes declared by a single `SnapshotManifestV1` (256 MiB).
pub const MAX_SNAP_WIRE_BYTES: u64 = 256 * 1024 * 1024;
/// Hard cap on total decoded state bytes (512 MiB).
pub const MAX_SNAPSHOT_DECODE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum number of consecutive `Delta` checkpoints applied over a `Base`.
pub const MAX_DELTA_CHAIN_LEN: usize = 8;

/// Hard wire bound on a serialized `SnapshotManifestV1` (enforced before decoding).
pub const MAX_MANIFEST_WIRE_BYTES: usize = 1024 + MAX_SNAP_UNITS * 128;

/// Delta-vs-Full size cutoff: if `delta_len * 100 >= full_len * 70`, emit `FullUnit`.
pub const DELTA_FULL_THRESHOLD_NUM: usize = 70;
pub const DELTA_FULL_THRESHOLD_DEN: usize = 100;

/// Unit encoding tags in `SnapshotUnitDesc::encoding`.
pub const UNIT_ENC_FULL: u8 = 0;
pub const UNIT_ENC_DELTA: u8 = 1;
pub const UNIT_ENC_UNCHANGED: u8 = 2;

/// Number of non-account domain units.
pub const N_DOMAIN_UNITS: usize = 16;
/// Total canonical unit tags (`256` account buckets + `16` domains).
pub const TOTAL_UNIT_TAGS: usize = N_ACCOUNT_BUCKETS + N_DOMAIN_UNITS;

// ============================================================================
// Errors
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapV4Error {
    InvalidMagic,
    UnsupportedVersion(u16),
    ChainIdMismatch {
        expected: u64,
        got: u64,
    },
    ShardIdMismatch {
        expected: u32,
        got: u32,
    },
    HeightMismatch {
        expected: u64,
        got: u64,
    },
    BoundaryHashMismatch,
    StateRootMismatch,
    EmptyValidatorSet,
    ValidatorSetHashMismatch,
    UnauthorizedPublisher,
    InvalidSignature,
    MissingPublisherKey,
    TooManyUnits {
        count: usize,
        max: usize,
    },
    WireBytesLimitExceeded {
        bytes: u64,
        max: u64,
    },
    DecodeBytesLimitExceeded {
        bytes: u64,
        max: u64,
    },
    ChunkTooLarge {
        len: usize,
        max: usize,
    },
    ManifestTooLarge {
        len: usize,
        max: usize,
    },
    ZeroLenNonUnchangedChunk {
        unit_tag: u16,
        sub_index: u16,
    },
    NonZeroUnchangedChunk {
        unit_tag: u16,
        sub_index: u16,
    },
    WireBytesSumMismatch {
        declared: u64,
        sum: u64,
    },
    UncompressedSmallerThanWire {
        uncompressed: u64,
        wire: u64,
    },
    UnitsMerkleRootMismatch,
    InvalidMerkleProof,
    UnknownUnitTag(u16),
    UnsortedOrDuplicateUnit {
        unit_tag: u16,
        sub_index: u16,
    },
    MissingUnitDescriptor {
        unit_tag: u16,
    },
    NonContiguousSubIndex {
        unit_tag: u16,
        expected: u16,
        got: u16,
    },
    InvalidEncodingForKind {
        kind: &'static str,
        unit_tag: u16,
        encoding: u8,
    },
    InvalidKind {
        expected: &'static str,
    },
    DeltaChainTooLong {
        len: usize,
        max: usize,
    },
    NonMonotonicDeltaChain {
        prev_height: u64,
        next_height: u64,
    },
    DeltaBaseStateRootMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    DeltaBaseUnitHashMismatch {
        unit_tag: u16,
    },
    ChunkHashMismatch {
        unit_tag: u16,
        sub_index: u16,
    },
    ChunkByteLenMismatch {
        unit_tag: u16,
        sub_index: u16,
        expected: usize,
        actual: usize,
    },
    UnitHashMismatch {
        unit_tag: u16,
        sub_index: u16,
    },
    MissingChunk {
        unit_tag: u16,
        sub_index: u16,
    },
    UnexpectedChunk {
        unit_tag: u16,
        sub_index: u16,
    },
    UnsortedOrDuplicateAccount {
        bucket: u8,
    },
    WrongBucketAddress {
        bucket: u8,
        addr_first_byte: u8,
    },
    BucketMismatch {
        expected: u8,
        got: u8,
    },
    SubChunkCountMismatch {
        unit_tag: u16,
        expected: u16,
        got: u16,
    },
    TooManyAccountsInChunk {
        bucket: u8,
        count: usize,
        max: usize,
    },
    UnsortedOrDuplicateKey {
        domain: &'static str,
    },
    UpsertDeleteOverlap {
        domain: &'static str,
    },
    DeleteMissingKey {
        domain: &'static str,
    },
    BincodeDecode(String),
    BincodeEncode(String),
    Overflow(&'static str),
    SigningFailed,
    PqKeyValidation(String),
    EngineRestore(String),
}

impl std::fmt::Display for SnapV4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid SnapV4 manifest magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported SnapV4 manifest version {v}"),
            Self::ChainIdMismatch { expected, got } => {
                write!(f, "chain_id mismatch: expected {expected}, got {got}")
            }
            Self::ShardIdMismatch { expected, got } => {
                write!(f, "shard_id mismatch: expected {expected}, got {got}")
            }
            Self::HeightMismatch { expected, got } => {
                write!(f, "target_height mismatch: expected {expected}, got {got}")
            }
            Self::BoundaryHashMismatch => write!(f, "target_block_hash != trusted_boundary_hash"),
            Self::StateRootMismatch => write!(f, "state_root != trusted_state_root"),
            Self::EmptyValidatorSet => write!(f, "trusted validator set is empty"),
            Self::ValidatorSetHashMismatch => write!(f, "validator_set_hash mismatch"),
            Self::UnauthorizedPublisher => {
                write!(f, "publisher_id has zero voting power in validator_set")
            }
            Self::InvalidSignature => write!(f, "invalid Falcon-512 manifest signature"),
            Self::MissingPublisherKey => write!(f, "missing Falcon-512 key for publisher_id"),
            Self::TooManyUnits { count, max } => {
                write!(f, "units count {count} exceeds MAX_SNAP_UNITS ({max})")
            }
            Self::WireBytesLimitExceeded { bytes, max } => {
                write!(
                    f,
                    "total_wire_bytes {bytes} exceeds MAX_SNAP_WIRE_BYTES ({max})"
                )
            }
            Self::DecodeBytesLimitExceeded { bytes, max } => {
                write!(
                    f,
                    "total_uncompressed_bytes {bytes} exceeds MAX_SNAPSHOT_DECODE_BYTES ({max})"
                )
            }
            Self::ChunkTooLarge { len, max } => {
                write!(
                    f,
                    "chunk byte_len {len} exceeds MAX_SNAP_CHUNK_BYTES ({max})"
                )
            }
            Self::ManifestTooLarge { len, max } => {
                write!(
                    f,
                    "manifest wire bytes {len} exceeds MAX_MANIFEST_WIRE_BYTES ({max})"
                )
            }
            Self::ZeroLenNonUnchangedChunk {
                unit_tag,
                sub_index,
            } => write!(
                f,
                "unit ({unit_tag}, {sub_index}) has byte_len == 0 for non-UnchangedRef encoding"
            ),
            Self::NonZeroUnchangedChunk {
                unit_tag,
                sub_index,
            } => write!(
                f,
                "UnchangedRef unit ({unit_tag}, {sub_index}) has non-zero byte_len or chunk_hash"
            ),
            Self::WireBytesSumMismatch { declared, sum } => write!(
                f,
                "manifest total_wire_bytes ({declared}) != sum of unit byte_len ({sum})"
            ),
            Self::UncompressedSmallerThanWire { uncompressed, wire } => write!(
                f,
                "total_uncompressed_bytes ({uncompressed}) < total_wire_bytes ({wire})"
            ),
            Self::UnitsMerkleRootMismatch => write!(f, "units_merkle_root mismatch"),
            Self::InvalidMerkleProof => write!(f, "invalid unit Merkle proof"),
            Self::UnknownUnitTag(tag) => write!(f, "unknown unit_tag {tag}"),
            Self::UnsortedOrDuplicateUnit {
                unit_tag,
                sub_index,
            } => write!(
                f,
                "unsorted or duplicate SnapshotUnitDesc ({unit_tag}, {sub_index})"
            ),
            Self::MissingUnitDescriptor { unit_tag } => {
                write!(f, "missing SnapshotUnitDesc for unit_tag {unit_tag}")
            }
            Self::NonContiguousSubIndex {
                unit_tag,
                expected,
                got,
            } => write!(
                f,
                "non-contiguous sub_index for unit_tag {unit_tag}: expected {expected}, got {got}"
            ),
            Self::InvalidEncodingForKind {
                kind,
                unit_tag,
                encoding,
            } => write!(
                f,
                "invalid encoding {encoding} for {kind} unit_tag {unit_tag}"
            ),
            Self::InvalidKind { expected } => write!(f, "expected SnapshotKind::{expected}"),
            Self::DeltaChainTooLong { len, max } => write!(
                f,
                "delta chain length {len} exceeds MAX_DELTA_CHAIN_LEN ({max})"
            ),
            Self::NonMonotonicDeltaChain {
                prev_height,
                next_height,
            } => write!(
                f,
                "non-monotonic delta chain: prev_height={prev_height}, next_height={next_height}"
            ),
            Self::DeltaBaseStateRootMismatch { expected, actual } => write!(
                f,
                "delta base_state_root mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            ),
            Self::DeltaBaseUnitHashMismatch { unit_tag } => {
                write!(f, "delta base unit_hash mismatch for unit_tag {unit_tag}")
            }
            Self::ChunkHashMismatch {
                unit_tag,
                sub_index,
            } => write!(f, "chunk BLAKE3 hash mismatch for ({unit_tag}, {sub_index})"),
            Self::ChunkByteLenMismatch {
                unit_tag,
                sub_index,
                expected,
                actual,
            } => write!(
                f,
                "chunk byte_len mismatch for ({unit_tag}, {sub_index}): expected {expected}, got {actual}"
            ),
            Self::UnitHashMismatch {
                unit_tag,
                sub_index,
            } => write!(f, "unit_hash mismatch for ({unit_tag}, {sub_index})"),
            Self::MissingChunk {
                unit_tag,
                sub_index,
            } => write!(f, "missing chunk ({unit_tag}, {sub_index})"),
            Self::UnexpectedChunk {
                unit_tag,
                sub_index,
            } => write!(f, "unexpected chunk ({unit_tag}, {sub_index})"),
            Self::UnsortedOrDuplicateAccount { bucket } => {
                write!(f, "unsorted or duplicate account in bucket {bucket}")
            }
            Self::WrongBucketAddress {
                bucket,
                addr_first_byte,
            } => write!(
                f,
                "account address first byte {addr_first_byte} != bucket {bucket}"
            ),
            Self::BucketMismatch { expected, got } => {
                write!(f, "chunk bucket mismatch: expected {expected}, got {got}")
            }
            Self::SubChunkCountMismatch {
                unit_tag,
                expected,
                got,
            } => write!(
                f,
                "sub-chunk count mismatch for unit_tag {unit_tag}: expected {expected}, got {got}"
            ),
            Self::TooManyAccountsInChunk { bucket, count, max } => write!(
                f,
                "bucket {bucket} chunk has {count} accounts > MAX_ACCOUNTS_PER_CHUNK ({max})"
            ),
            Self::UnsortedOrDuplicateKey { domain } => {
                write!(f, "unsorted or duplicate key in {domain}")
            }
            Self::UpsertDeleteOverlap { domain } => {
                write!(f, "key appears in both upserts and deletes for {domain}")
            }
            Self::DeleteMissingKey { domain } => {
                write!(f, "delta deletes non-existent key in {domain}")
            }
            Self::BincodeDecode(e) => write!(f, "strict bincode decode error: {e}"),
            Self::BincodeEncode(e) => write!(f, "canonical bincode encode error: {e}"),
            Self::Overflow(what) => write!(f, "integer overflow in {what}"),
            Self::SigningFailed => write!(f, "Falcon-512 manifest signing failed"),
            Self::PqKeyValidation(e) => write!(f, "pq_keys validation error: {e}"),
            Self::EngineRestore(e) => write!(f, "engine restore error: {e}"),
        }
    }
}

impl std::error::Error for SnapV4Error {}

// ============================================================================
// Unit Tags & Domain Identifiers
// ============================================================================

/// Non-account domain unit identifiers (`unit_tag` 256..=271).
///
/// NOTE: `safety_record_v1`, `ConsensusCheckpoint`, and `VoteWatermark` are
/// explicitly absent and never represented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum DomainUnitId {
    Scalars = 256,
    Tokens = 257,
    Contracts = 258,
    Orderbooks = 259,
    Pmm = 260,
    OrderEscrow = 261,
    Staking = 262,
    Governance = 263,
    Oracle = 264,
    SessionKeys = 265,
    Bridge = 266,
    ZkMl = 267,
    CrossShard = 268,
    CnVrfV3 = 269,
    PqKeys = 270,
    EvmBindings = 271,
}

impl DomainUnitId {
    pub const ALL: [DomainUnitId; N_DOMAIN_UNITS] = [
        Self::Scalars,
        Self::Tokens,
        Self::Contracts,
        Self::Orderbooks,
        Self::Pmm,
        Self::OrderEscrow,
        Self::Staking,
        Self::Governance,
        Self::Oracle,
        Self::SessionKeys,
        Self::Bridge,
        Self::ZkMl,
        Self::CrossShard,
        Self::CnVrfV3,
        Self::PqKeys,
        Self::EvmBindings,
    ];

    pub const fn tag(self) -> u16 {
        self as u16
    }

    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            256 => Some(Self::Scalars),
            257 => Some(Self::Tokens),
            258 => Some(Self::Contracts),
            259 => Some(Self::Orderbooks),
            260 => Some(Self::Pmm),
            261 => Some(Self::OrderEscrow),
            262 => Some(Self::Staking),
            263 => Some(Self::Governance),
            264 => Some(Self::Oracle),
            265 => Some(Self::SessionKeys),
            266 => Some(Self::Bridge),
            267 => Some(Self::ZkMl),
            268 => Some(Self::CrossShard),
            269 => Some(Self::CnVrfV3),
            270 => Some(Self::PqKeys),
            271 => Some(Self::EvmBindings),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Scalars => "Scalars",
            Self::Tokens => "Tokens",
            Self::Contracts => "Contracts",
            Self::Orderbooks => "Orderbooks",
            Self::Pmm => "Pmm",
            Self::OrderEscrow => "OrderEscrow",
            Self::Staking => "Staking",
            Self::Governance => "Governance",
            Self::Oracle => "Oracle",
            Self::SessionKeys => "SessionKeys",
            Self::Bridge => "Bridge",
            Self::ZkMl => "ZkMl",
            Self::CrossShard => "CrossShard",
            Self::CnVrfV3 => "CnVrfV3",
            Self::PqKeys => "PqKeys",
            Self::EvmBindings => "EvmBindings",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnitKind {
    AccountBucket(u8),
    Domain(DomainUnitId),
}

impl UnitKind {
    pub const fn from_tag(tag: u16) -> Option<Self> {
        if tag < N_ACCOUNT_BUCKETS as u16 {
            Some(Self::AccountBucket(tag as u8))
        } else {
            match DomainUnitId::from_tag(tag) {
                Some(d) => Some(Self::Domain(d)),
                None => None,
            }
        }
    }
}

// ============================================================================
// Manifest Types & Pre-Allocation Bounded Deserializer (§2.2)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotKind {
    Base,
    Delta {
        base_height: u64,
        base_state_root: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotUnitDesc {
    pub unit_tag: u16,
    pub sub_index: u16,
    pub encoding: u8,
    pub unit_hash: [u8; 32],
    pub chunk_hash: [u8; 32],
    pub byte_len: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifestV1 {
    pub magic: [u8; 8],
    pub version: u16,
    pub chain_id: u64,
    pub shard_id: u32,
    pub kind: SnapshotKind,
    pub target_height: u64,
    pub target_block_hash: [u8; 32],
    pub target_state_root: [u8; 32],
    pub validator_set_hash: [u8; 32],
    pub total_wire_bytes: u64,
    pub total_uncompressed_bytes: u64,
    pub units_merkle_root: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_units")]
    pub units: Vec<SnapshotUnitDesc>,
    pub publisher_id: [u8; 32],
    #[serde(deserialize_with = "deserialize_bounded_sig")]
    pub publisher_sig: Vec<u8>,
}

fn deserialize_bounded_units<'de, D>(deserializer: D) -> Result<Vec<SnapshotUnitDesc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UnitsVisitor;

    impl<'de> serde::de::Visitor<'de> for UnitsVisitor {
        type Value = Vec<SnapshotUnitDesc>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded sequence of SnapshotUnitDesc")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            // Enforce MAX_SNAP_UNITS BEFORE any Vec::with_capacity allocation.
            if let Some(hint) = seq.size_hint() {
                if hint > MAX_SNAP_UNITS {
                    return Err(serde::de::Error::custom(format!(
                        "manifest units count {hint} exceeds MAX_SNAP_UNITS ({MAX_SNAP_UNITS})"
                    )));
                }
            }
            let cap = seq.size_hint().unwrap_or(0).min(MAX_SNAP_UNITS);
            let mut out = Vec::with_capacity(cap);
            while let Some(elem) = seq.next_element::<SnapshotUnitDesc>()? {
                if out.len() >= MAX_SNAP_UNITS {
                    return Err(serde::de::Error::custom(format!(
                        "manifest units count exceeds MAX_SNAP_UNITS ({MAX_SNAP_UNITS})"
                    )));
                }
                out.push(elem);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(UnitsVisitor)
}

fn deserialize_bounded_sig<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct SigVisitor;

    impl<'de> serde::de::Visitor<'de> for SigVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded Falcon-512 signature")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if let Some(hint) = seq.size_hint() {
                if hint > FALCON512_SIG_LEN {
                    return Err(serde::de::Error::custom(format!(
                        "manifest publisher_sig length {hint} exceeds FALCON512_SIG_LEN ({FALCON512_SIG_LEN})"
                    )));
                }
            }
            let cap = seq.size_hint().unwrap_or(0).min(FALCON512_SIG_LEN);
            let mut out = Vec::with_capacity(cap);
            while let Some(b) = seq.next_element::<u8>()? {
                if out.len() >= FALCON512_SIG_LEN {
                    return Err(serde::de::Error::custom(format!(
                        "manifest publisher_sig length exceeds FALCON512_SIG_LEN ({FALCON512_SIG_LEN})"
                    )));
                }
                out.push(b);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(SigVisitor)
}

// ============================================================================
// Strict Canonical Serialization & Hashing Primitives
// ============================================================================

pub fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, SnapV4Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(value)
        .map_err(|e| SnapV4Error::BincodeEncode(e.to_string()))
}

pub fn decode_canonical_exact<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: u64,
) -> Result<T, SnapV4Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| SnapV4Error::BincodeDecode(e.to_string()))
}

pub fn encode_manifest_strict(manifest: &SnapshotManifestV1) -> Result<Vec<u8>, SnapV4Error> {
    let bytes = encode_canonical(manifest)?;
    if bytes.len() > MAX_MANIFEST_WIRE_BYTES {
        return Err(SnapV4Error::ManifestTooLarge {
            len: bytes.len(),
            max: MAX_MANIFEST_WIRE_BYTES,
        });
    }
    Ok(bytes)
}

pub fn decode_manifest_strict(bytes: &[u8]) -> Result<SnapshotManifestV1, SnapV4Error> {
    if bytes.len() > MAX_MANIFEST_WIRE_BYTES {
        return Err(SnapV4Error::ManifestTooLarge {
            len: bytes.len(),
            max: MAX_MANIFEST_WIRE_BYTES,
        });
    }
    decode_canonical_exact(bytes, MAX_MANIFEST_WIRE_BYTES as u64)
}

pub fn empty_bucket_hash() -> [u8; 32] {
    *blake3::hash(SNAP_EMPTY_BUCKET_DOMAIN).as_bytes()
}

pub fn compute_unit_hash(unit_tag: u16, sub_index: u16, raw_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAP_UNIT_HASH_DOMAIN);
    hasher.update(&unit_tag.to_le_bytes());
    hasher.update(&sub_index.to_le_bytes());
    hasher.update(raw_bytes);
    *hasher.finalize().as_bytes()
}

pub fn canonical_vset_hash(vset: &ValidatorSet) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAP_VSET_HASH_DOMAIN);
    hasher.update(&(vset.validators.len() as u64).to_le_bytes());
    for (id, power) in &vset.validators {
        hasher.update(id);
        hasher.update(&power.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Units Merkle Tree & Proofs
// ============================================================================

fn canonical_unit_desc_bytes(desc: &SnapshotUnitDesc) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 2 + 1 + 32 + 32 + 4);
    out.extend_from_slice(&desc.unit_tag.to_le_bytes());
    out.extend_from_slice(&desc.sub_index.to_le_bytes());
    out.push(desc.encoding);
    out.extend_from_slice(&desc.unit_hash);
    out.extend_from_slice(&desc.chunk_hash);
    out.extend_from_slice(&desc.byte_len.to_le_bytes());
    out
}

fn hash_merkle_leaf(desc: &SnapshotUnitDesc) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAP_MERKLE_LEAF_DOMAIN);
    hasher.update(&canonical_unit_desc_bytes(desc));
    *hasher.finalize().as_bytes()
}

fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAP_MERKLE_NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

pub fn compute_units_merkle_root(units: &[SnapshotUnitDesc]) -> [u8; 32] {
    if units.is_empty() {
        return *blake3::hash(SNAP_MERKLE_EMPTY_DOMAIN).as_bytes();
    }
    let mut level: Vec<[u8; 32]> = units.iter().map(hash_merkle_leaf).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_merkle_node(&left, &right));
        }
        level = next;
    }
    level[0]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitMerkleProof {
    pub index: usize,
    pub total_leaves: usize,
    pub siblings: Vec<[u8; 32]>,
}

pub fn generate_unit_merkle_proof(
    units: &[SnapshotUnitDesc],
    index: usize,
) -> Result<UnitMerkleProof, SnapV4Error> {
    if units.is_empty() || units.len() > MAX_SNAP_UNITS || index >= units.len() {
        return Err(SnapV4Error::InvalidMerkleProof);
    }
    let total_leaves = units.len();
    let mut level: Vec<[u8; 32]> = units.iter().map(hash_merkle_leaf).collect();
    let mut idx = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            if idx + 1 < level.len() {
                idx + 1
            } else {
                idx
            }
        } else {
            idx - 1
        };
        siblings.push(level[sibling_idx]);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_merkle_node(&left, &right));
        }
        level = next;
        idx /= 2;
    }
    Ok(UnitMerkleProof {
        index,
        total_leaves,
        siblings,
    })
}

pub fn verify_unit_merkle_proof(
    root: &[u8; 32],
    desc: &SnapshotUnitDesc,
    proof: &UnitMerkleProof,
) -> bool {
    if proof.total_leaves == 0
        || proof.total_leaves > MAX_SNAP_UNITS
        || proof.index >= proof.total_leaves
    {
        return false;
    }
    let mut expected_depth = 0usize;
    let mut n = proof.total_leaves;
    while n > 1 {
        expected_depth += 1;
        n = n.div_ceil(2);
    }
    if proof.siblings.len() != expected_depth {
        return false;
    }
    let mut cur = hash_merkle_leaf(desc);
    let mut idx = proof.index;
    let mut level_len = proof.total_leaves;
    for sib in &proof.siblings {
        if idx >= level_len {
            return false;
        }
        cur = if idx.is_multiple_of(2) {
            hash_merkle_node(&cur, sib)
        } else {
            hash_merkle_node(sib, &cur)
        };
        idx /= 2;
        level_len = level_len.div_ceil(2);
    }
    &cur == root
}

// ============================================================================
// Manifest Signing & Pre-Fetch Verification (§2.2)
// ============================================================================

pub fn canonical_manifest_body_bytes(manifest: &SnapshotManifestV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + manifest.units.len() * 73);
    out.extend_from_slice(&manifest.magic);
    out.extend_from_slice(&manifest.version.to_le_bytes());
    out.extend_from_slice(&manifest.chain_id.to_le_bytes());
    out.extend_from_slice(&manifest.shard_id.to_le_bytes());
    match &manifest.kind {
        SnapshotKind::Base => out.push(0),
        SnapshotKind::Delta {
            base_height,
            base_state_root,
        } => {
            out.push(1);
            out.extend_from_slice(&base_height.to_le_bytes());
            out.extend_from_slice(base_state_root);
        }
    }
    out.extend_from_slice(&manifest.target_height.to_le_bytes());
    out.extend_from_slice(&manifest.target_block_hash);
    out.extend_from_slice(&manifest.target_state_root);
    out.extend_from_slice(&manifest.validator_set_hash);
    out.extend_from_slice(&manifest.total_wire_bytes.to_le_bytes());
    out.extend_from_slice(&manifest.total_uncompressed_bytes.to_le_bytes());
    out.extend_from_slice(&manifest.units_merkle_root);
    out.extend_from_slice(&(manifest.units.len() as u64).to_le_bytes());
    for desc in &manifest.units {
        out.extend_from_slice(&canonical_unit_desc_bytes(desc));
    }
    out.extend_from_slice(&manifest.publisher_id);
    out
}

pub fn manifest_signing_digest(manifest: &SnapshotManifestV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAP_MANIFEST_SIG_DOMAIN);
    hasher.update(&canonical_manifest_body_bytes(manifest));
    *hasher.finalize().as_bytes()
}

pub fn sign_manifest(
    manifest: &mut SnapshotManifestV1,
    keypair: &FalconKeypair,
) -> Result<(), SnapV4Error> {
    manifest.publisher_id = keypair.validator_id();
    let digest = manifest_signing_digest(manifest);
    let sig = keypair.sign(&digest);
    if sig.len() != FALCON512_SIG_LEN {
        return Err(SnapV4Error::SigningFailed);
    }
    manifest.publisher_sig = sig;
    Ok(())
}

/// Consensus-verified anchor inputs required BEFORE fetching or processing any units.
#[derive(Clone, Copy, Debug)]
pub struct TrustedSnapshotAnchor<'a> {
    pub chain_id: u64,
    pub shard_id: u32,
    pub target_height: u64,
    pub trusted_boundary_hash: [u8; 32],
    pub trusted_state_root: [u8; 32],
    pub validator_set: &'a ValidatorSet,
}

/// Pre-fetch manifest validation using the global rotation-aware PQ key registry
/// (`crate::consensus::pq_key_at_height`).
pub fn validate_manifest_pre_fetch(
    manifest: &SnapshotManifestV1,
    anchor: &TrustedSnapshotAnchor<'_>,
) -> Result<(), SnapV4Error> {
    validate_manifest_pre_fetch_with_key_resolver(manifest, anchor, pq_key_at_height)
}

/// Pre-fetch manifest validation with an explicit `(publisher_id, height) -> (PqScheme, pk)`
/// resolver. Enforces ALL bounds, anchor bindings, Merkle root, and Falcon-512
/// signature BEFORE any unit buffer allocation or chunk download.
pub fn validate_manifest_pre_fetch_with_key_resolver<F>(
    manifest: &SnapshotManifestV1,
    anchor: &TrustedSnapshotAnchor<'_>,
    key_resolver: F,
) -> Result<(), SnapV4Error>
where
    F: Fn(&ValidatorId, u64) -> Option<(PqScheme, Vec<u8>)>,
{
    if manifest.magic != SNAP_MANIFEST_MAGIC {
        return Err(SnapV4Error::InvalidMagic);
    }
    if manifest.version != SNAP_MANIFEST_VERSION {
        return Err(SnapV4Error::UnsupportedVersion(manifest.version));
    }
    if manifest.chain_id != anchor.chain_id {
        return Err(SnapV4Error::ChainIdMismatch {
            expected: anchor.chain_id,
            got: manifest.chain_id,
        });
    }
    if manifest.shard_id != anchor.shard_id {
        return Err(SnapV4Error::ShardIdMismatch {
            expected: anchor.shard_id,
            got: manifest.shard_id,
        });
    }
    if manifest.target_height != anchor.target_height {
        return Err(SnapV4Error::HeightMismatch {
            expected: anchor.target_height,
            got: manifest.target_height,
        });
    }
    if manifest.target_block_hash != anchor.trusted_boundary_hash {
        return Err(SnapV4Error::BoundaryHashMismatch);
    }
    if manifest.target_state_root != anchor.trusted_state_root {
        return Err(SnapV4Error::StateRootMismatch);
    }
    if anchor.validator_set.validators.is_empty() {
        return Err(SnapV4Error::EmptyValidatorSet);
    }
    if manifest.validator_set_hash != canonical_vset_hash(anchor.validator_set) {
        return Err(SnapV4Error::ValidatorSetHashMismatch);
    }
    if anchor.validator_set.power_of(&manifest.publisher_id) == 0 {
        return Err(SnapV4Error::UnauthorizedPublisher);
    }

    if let SnapshotKind::Delta { base_height, .. } = manifest.kind {
        if base_height >= manifest.target_height {
            return Err(SnapV4Error::NonMonotonicDeltaChain {
                prev_height: base_height,
                next_height: manifest.target_height,
            });
        }
    }

    if manifest.units.len() > MAX_SNAP_UNITS {
        return Err(SnapV4Error::TooManyUnits {
            count: manifest.units.len(),
            max: MAX_SNAP_UNITS,
        });
    }
    if manifest.total_wire_bytes > MAX_SNAP_WIRE_BYTES {
        return Err(SnapV4Error::WireBytesLimitExceeded {
            bytes: manifest.total_wire_bytes,
            max: MAX_SNAP_WIRE_BYTES,
        });
    }
    if manifest.total_uncompressed_bytes > MAX_SNAPSHOT_DECODE_BYTES {
        return Err(SnapV4Error::DecodeBytesLimitExceeded {
            bytes: manifest.total_uncompressed_bytes,
            max: MAX_SNAPSHOT_DECODE_BYTES,
        });
    }
    if manifest.total_uncompressed_bytes < manifest.total_wire_bytes {
        return Err(SnapV4Error::UncompressedSmallerThanWire {
            uncompressed: manifest.total_uncompressed_bytes,
            wire: manifest.total_wire_bytes,
        });
    }

    let is_base = matches!(manifest.kind, SnapshotKind::Base);
    let mut sum_wire_bytes: u64 = 0;
    let mut prev_tag_sub: Option<(u16, u16)> = None;
    let mut seen_tags = [false; TOTAL_UNIT_TAGS];

    for desc in &manifest.units {
        if UnitKind::from_tag(desc.unit_tag).is_none() {
            return Err(SnapV4Error::UnknownUnitTag(desc.unit_tag));
        }

        if let Some((prev_tag, prev_sub)) = prev_tag_sub {
            if (desc.unit_tag, desc.sub_index) <= (prev_tag, prev_sub) {
                return Err(SnapV4Error::UnsortedOrDuplicateUnit {
                    unit_tag: desc.unit_tag,
                    sub_index: desc.sub_index,
                });
            }
            if desc.unit_tag == prev_tag {
                let expected_sub = prev_sub
                    .checked_add(1)
                    .ok_or(SnapV4Error::Overflow("sub_index"))?;
                if desc.sub_index != expected_sub {
                    return Err(SnapV4Error::NonContiguousSubIndex {
                        unit_tag: desc.unit_tag,
                        expected: expected_sub,
                        got: desc.sub_index,
                    });
                }
            } else if desc.sub_index != 0 {
                return Err(SnapV4Error::NonContiguousSubIndex {
                    unit_tag: desc.unit_tag,
                    expected: 0,
                    got: desc.sub_index,
                });
            }
        } else if desc.sub_index != 0 {
            return Err(SnapV4Error::NonContiguousSubIndex {
                unit_tag: desc.unit_tag,
                expected: 0,
                got: desc.sub_index,
            });
        }
        prev_tag_sub = Some((desc.unit_tag, desc.sub_index));
        seen_tags[desc.unit_tag as usize] = true;

        match desc.encoding {
            UNIT_ENC_FULL => {
                if desc.byte_len == 0 {
                    return Err(SnapV4Error::ZeroLenNonUnchangedChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    });
                }
                if (desc.byte_len as usize) > MAX_SNAP_CHUNK_BYTES {
                    return Err(SnapV4Error::ChunkTooLarge {
                        len: desc.byte_len as usize,
                        max: MAX_SNAP_CHUNK_BYTES,
                    });
                }
            }
            UNIT_ENC_DELTA => {
                if is_base {
                    return Err(SnapV4Error::InvalidEncodingForKind {
                        kind: "Base",
                        unit_tag: desc.unit_tag,
                        encoding: desc.encoding,
                    });
                }
                if desc.sub_index != 0 {
                    return Err(SnapV4Error::NonContiguousSubIndex {
                        unit_tag: desc.unit_tag,
                        expected: 0,
                        got: desc.sub_index,
                    });
                }
                if desc.byte_len == 0 {
                    return Err(SnapV4Error::ZeroLenNonUnchangedChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    });
                }
                if (desc.byte_len as usize) > MAX_SNAP_CHUNK_BYTES {
                    return Err(SnapV4Error::ChunkTooLarge {
                        len: desc.byte_len as usize,
                        max: MAX_SNAP_CHUNK_BYTES,
                    });
                }
            }
            UNIT_ENC_UNCHANGED => {
                if is_base {
                    if desc.unit_tag as usize >= N_ACCOUNT_BUCKETS {
                        return Err(SnapV4Error::InvalidEncodingForKind {
                            kind: "Base(Domain)",
                            unit_tag: desc.unit_tag,
                            encoding: desc.encoding,
                        });
                    }
                    if desc.unit_hash != empty_bucket_hash() {
                        return Err(SnapV4Error::InvalidEncodingForKind {
                            kind: "Base(NonEmptyUnchanged)",
                            unit_tag: desc.unit_tag,
                            encoding: desc.encoding,
                        });
                    }
                }
                if desc.sub_index != 0 {
                    return Err(SnapV4Error::NonContiguousSubIndex {
                        unit_tag: desc.unit_tag,
                        expected: 0,
                        got: desc.sub_index,
                    });
                }
                if desc.byte_len != 0 || desc.chunk_hash != [0u8; 32] {
                    return Err(SnapV4Error::NonZeroUnchangedChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    });
                }
            }
            other => {
                return Err(SnapV4Error::InvalidEncodingForKind {
                    kind: "Manifest",
                    unit_tag: desc.unit_tag,
                    encoding: other,
                });
            }
        }

        sum_wire_bytes = sum_wire_bytes
            .checked_add(desc.byte_len as u64)
            .ok_or(SnapV4Error::Overflow("total_wire_bytes"))?;
    }

    for (tag, &present) in seen_tags.iter().enumerate() {
        if !present {
            return Err(SnapV4Error::MissingUnitDescriptor {
                unit_tag: tag as u16,
            });
        }
    }

    if sum_wire_bytes != manifest.total_wire_bytes {
        return Err(SnapV4Error::WireBytesSumMismatch {
            declared: manifest.total_wire_bytes,
            sum: sum_wire_bytes,
        });
    }

    let computed_merkle = compute_units_merkle_root(&manifest.units);
    if computed_merkle != manifest.units_merkle_root {
        return Err(SnapV4Error::UnitsMerkleRootMismatch);
    }

    let (scheme, pk) = key_resolver(&manifest.publisher_id, manifest.target_height)
        .ok_or(SnapV4Error::MissingPublisherKey)?;
    if scheme != PqScheme::Falcon512 || scheme.is_disabled() {
        return Err(SnapV4Error::InvalidSignature);
    }
    let digest = manifest_signing_digest(manifest);
    if !verify_pq_signature(PqScheme::Falcon512, &pk, &digest, &manifest.publisher_sig) {
        return Err(SnapV4Error::InvalidSignature);
    }

    Ok(())
}

// ============================================================================
// Canonical Domain & Diff Wire Structures
// ============================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalScalars {
    pub penalty: BTreeMap<[u8; 32], u64>,
    pub total_minted_nano: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarsDelta {
    pub expected_base_hash: [u8; 32],
    pub penalty_upserts: Vec<([u8; 32], u64)>,
    pub penalty_deletes: Vec<[u8; 32]>,
    pub total_minted_nano: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalTokenActor {
    pub id: [u8; 32],
    pub metadata: TokenMetadata,
    pub balances: BTreeMap<[u8; 32], u64>,
    pub allowances: BTreeMap<([u8; 32], [u8; 32]), u64>,
}

impl CanonicalTokenActor {
    pub fn from_actor(a: &TokenActor) -> Self {
        Self {
            id: a.id,
            metadata: a.metadata.clone(),
            balances: a.balances.iter().map(|(k, v)| (*k, *v)).collect(),
            allowances: a.allowances.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }

    pub fn to_actor(&self) -> TokenActor {
        TokenActor {
            id: self.id,
            metadata: self.metadata.clone(),
            balances: self.balances.iter().map(|(k, v)| (*k, *v)).collect(),
            allowances: self.allowances.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalTokenRegistry {
    pub tokens: BTreeMap<[u8; 32], CanonicalTokenActor>,
    pub next_nonce: u64,
}

impl CanonicalTokenRegistry {
    pub fn from_registry(r: &TokenRegistry) -> Self {
        Self {
            tokens: r
                .tokens
                .iter()
                .map(|(k, v)| (*k, CanonicalTokenActor::from_actor(v)))
                .collect(),
            next_nonce: r.next_nonce,
        }
    }

    pub fn to_registry(&self) -> TokenRegistry {
        TokenRegistry {
            tokens: self
                .tokens
                .iter()
                .map(|(k, v)| (*k, v.to_actor()))
                .collect(),
            next_nonce: self.next_nonce,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenChunk {
    pub sub_index: u16,
    pub total_sub_chunks: u16,
    pub next_nonce: u64,
    pub entries: Vec<CanonicalTokenActor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalContract {
    pub address: [u8; 32],
    pub creator: [u8; 32],
    pub code_hash: [u8; 32],
    pub code: Vec<u8>,
    pub storage: BTreeMap<i64, i64>,
    pub created_at: u64,
    pub paused: bool,
    pub balance: u64,
    pub abi: Option<ContractAbi>,
    pub source_hash: Option<[u8; 32]>,
}

impl CanonicalContract {
    pub fn from_contract(c: &Contract) -> Self {
        Self {
            address: c.address,
            creator: c.creator,
            code_hash: c.code_hash,
            code: c.code.clone(),
            storage: c.storage.iter().map(|(k, v)| (*k, *v)).collect(),
            created_at: c.created_at,
            paused: c.paused,
            balance: c.balance,
            abi: c.abi.clone(),
            source_hash: c.source_hash,
        }
    }

    pub fn to_contract(&self) -> Contract {
        Contract {
            address: self.address,
            creator: self.creator,
            code_hash: self.code_hash,
            code: self.code.clone(),
            storage: self.storage.iter().map(|(k, v)| (*k, *v)).collect(),
            created_at: self.created_at,
            paused: self.paused,
            balance: self.balance,
            abi: self.abi.clone(),
            source_hash: self.source_hash,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalContractRegistry {
    pub contracts: BTreeMap<[u8; 32], CanonicalContract>,
    pub next_nonce: u64,
    pub last_return_data: Vec<u8>,
}

impl CanonicalContractRegistry {
    pub fn from_registry(r: &ContractRegistry) -> Self {
        Self {
            contracts: r
                .contracts
                .iter()
                .map(|(k, v)| (*k, CanonicalContract::from_contract(v)))
                .collect(),
            next_nonce: r.next_nonce,
            last_return_data: r.last_return_data.clone(),
        }
    }

    pub fn to_registry(&self) -> ContractRegistry {
        ContractRegistry {
            contracts: self
                .contracts
                .iter()
                .map(|(k, v)| (*k, v.to_contract()))
                .collect(),
            next_nonce: self.next_nonce,
            last_return_data: self.last_return_data.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractChunk {
    pub sub_index: u16,
    pub total_sub_chunks: u16,
    pub next_nonce: u64,
    pub last_return_data: Vec<u8>,
    pub entries: Vec<CanonicalContract>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalOrderbookManager {
    pub books: BTreeMap<u32, OrderbookActor>,
}

impl CanonicalOrderbookManager {
    pub fn from_manager(m: &OrderbookManager) -> Self {
        Self {
            books: m.books.iter().map(|(k, v)| (*k, v.clone())).collect(),
        }
    }

    pub fn to_manager(&self) -> OrderbookManager {
        OrderbookManager {
            books: self.books.iter().map(|(k, v)| (*k, v.clone())).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPmm {
    pub pmm: PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalOrderEscrow {
    pub escrow: BTreeMap<(u32, u64), EscrowRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalStakingLedger {
    pub validators: BTreeMap<ValidatorId, ValidatorStake>,
    pub delegations: BTreeMap<(ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: BTreeMap<(ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<UnbondingEntry>,
    pub withdrawable: BTreeMap<(ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: BTreeMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: BTreeSet<[u8; 32]>,
    pub equivocation_dedup: BTreeSet<[u8; 32]>,
    pub validator_pq_keys: BTreeMap<ValidatorId, (PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules: BTreeMap<[u8; 32], TeamVestingSchedule>,
    pub reward_accumulators: BTreeMap<ValidatorId, ValidatorRewardState>,
    pub delegator_reward_checkpoints: BTreeMap<(ValidatorId, [u8; 32]), u128>,
    pub jail: BTreeMap<ValidatorId, JailRecord>,
    pub commission_schedule: BTreeMap<ValidatorId, CommissionSchedule>,
    pub redelegation_lock: BTreeMap<(ValidatorId, [u8; 32]), u64>,
    pub recent_full_exits: BTreeMap<ValidatorId, (u64, u64)>,
}

impl CanonicalStakingLedger {
    pub fn from_ledger(s: &StakingLedger) -> Self {
        Self {
            validators: s.validators.iter().map(|(k, v)| (*k, v.clone())).collect(),
            delegations: s.delegations.iter().map(|(k, v)| (*k, *v)).collect(),
            delegator_rewards: s.delegator_rewards.iter().map(|(k, v)| (*k, *v)).collect(),
            unbonding: s.unbonding.clone(),
            withdrawable: s.withdrawable.iter().map(|(k, v)| (*k, *v)).collect(),
            total_burned: s.total_burned,
            rewards_pool: s.rewards_pool,
            rewards_minted: s.rewards_minted,
            locked_governance: s.locked_governance.iter().map(|(k, v)| (*k, *v)).collect(),
            pq_equivocation_dedup: s.pq_equivocation_dedup.iter().copied().collect(),
            equivocation_dedup: s.equivocation_dedup.iter().copied().collect(),
            validator_pq_keys: s
                .validator_pq_keys
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            min_validator_bond: s.min_validator_bond,
            vesting_schedules: s.vesting_schedules.clone(),
            reward_accumulators: s
                .reward_accumulators
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            delegator_reward_checkpoints: s
                .delegator_reward_checkpoints
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            jail: s.jail.iter().map(|(k, v)| (*k, *v)).collect(),
            commission_schedule: s
                .commission_schedule
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            redelegation_lock: s.redelegation_lock.iter().map(|(k, v)| (*k, *v)).collect(),
            recent_full_exits: s.recent_full_exits.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }

    pub fn to_ledger(&self) -> StakingLedger {
        StakingLedger {
            validators: self
                .validators
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            delegations: self.delegations.iter().map(|(k, v)| (*k, *v)).collect(),
            delegator_rewards: self
                .delegator_rewards
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            unbonding: self.unbonding.clone(),
            withdrawable: self.withdrawable.iter().map(|(k, v)| (*k, *v)).collect(),
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self
                .locked_governance
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            pq_equivocation_dedup: self.pq_equivocation_dedup.iter().copied().collect(),
            equivocation_dedup: self.equivocation_dedup.iter().copied().collect(),
            validator_pq_keys: self
                .validator_pq_keys
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            min_validator_bond: self.min_validator_bond,
            vesting_schedules: self.vesting_schedules.clone(),
            reward_accumulators: self
                .reward_accumulators
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            delegator_reward_checkpoints: self
                .delegator_reward_checkpoints
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            jail: self.jail.iter().map(|(k, v)| (*k, *v)).collect(),
            commission_schedule: self
                .commission_schedule
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            redelegation_lock: self
                .redelegation_lock
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            recent_full_exits: self
                .recent_full_exits
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalProposal {
    pub id: u64,
    pub proposer: ValidatorId,
    pub title: String,
    pub action: crate::governance::GovAction,
    pub created_at: u64,
    pub voting_end: u64,
    pub yes: u128,
    pub no: u128,
    pub abstain: u128,
    pub voters: BTreeMap<[u8; 32], VoteChoice>,
    pub status: ProposalStatus,
    pub electorate: u128,
    pub electorate_weights: Option<BTreeMap<[u8; 32], u128>>,
    pub proposer_lock: u64,
    pub weights: BTreeMap<[u8; 32], u128>,
}

impl CanonicalProposal {
    pub fn from_proposal(p: &Proposal) -> Self {
        Self {
            id: p.id,
            proposer: p.proposer,
            title: p.title.clone(),
            action: p.action.clone(),
            created_at: p.created_at,
            voting_end: p.voting_end,
            yes: p.yes,
            no: p.no,
            abstain: p.abstain,
            voters: p.voters.iter().map(|(k, v)| (*k, *v)).collect(),
            status: p.status,
            electorate: p.electorate,
            electorate_weights: p.electorate_weights.clone(),
            proposer_lock: p.proposer_lock,
            weights: p.weights.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }

    pub fn to_proposal(&self) -> Proposal {
        Proposal {
            id: self.id,
            proposer: self.proposer,
            title: self.title.clone(),
            action: self.action.clone(),
            created_at: self.created_at,
            voting_end: self.voting_end,
            yes: self.yes,
            no: self.no,
            abstain: self.abstain,
            voters: self.voters.iter().map(|(k, v)| (*k, *v)).collect(),
            status: self.status,
            electorate: self.electorate,
            electorate_weights: self.electorate_weights.clone(),
            proposer_lock: self.proposer_lock,
            weights: self.weights.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalGovernance {
    pub proposals: BTreeMap<u64, CanonicalProposal>,
    pub next_id: u64,
    pub quorum_bps: u64,
    pub applied: AppliedParams,
    pub timelocks: BTreeMap<u64, u64>,
    pub gov_propose_nonces: BTreeSet<([u8; 32], u64)>,
}

impl CanonicalGovernance {
    pub fn from_governance(g: &Governance) -> Self {
        Self {
            proposals: g
                .proposals
                .iter()
                .map(|(k, v)| (*k, CanonicalProposal::from_proposal(v)))
                .collect(),
            next_id: g.next_id,
            quorum_bps: g.quorum_bps,
            applied: g.applied.clone(),
            timelocks: g.timelocks.iter().map(|(k, v)| (*k, *v)).collect(),
            gov_propose_nonces: g.gov_propose_nonces.iter().copied().collect(),
        }
    }

    pub fn to_governance(&self) -> Governance {
        Governance {
            proposals: self
                .proposals
                .iter()
                .map(|(k, v)| (*k, v.to_proposal()))
                .collect(),
            next_id: self.next_id,
            quorum_bps: self.quorum_bps,
            applied: self.applied.clone(),
            timelocks: self.timelocks.iter().map(|(k, v)| (*k, *v)).collect(),
            gov_propose_nonces: self.gov_propose_nonces.iter().copied().collect(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CanonicalCrossShard {
    pub engine_consumed: BTreeSet<CrossShardKey>,
    pub runtime_consumed: BTreeSet<CrossShardKey>,
    pub produced: BTreeMap<[u8; 32], (Transaction, u64)>,
    pub completed: BTreeSet<[u8; 32]>,
    pub xpc: BTreeMap<[u8; 32], XpcRecord>,
}

impl CanonicalCrossShard {
    pub fn from_replay(r: &CrossShardReplaySnapshot) -> Self {
        let mut produced = BTreeMap::new();
        for (h, tx, height) in &r.produced {
            produced.entry(*h).or_insert_with(|| (tx.clone(), *height));
        }
        let mut xpc = BTreeMap::new();
        for rec in &r.xpc {
            xpc.insert(rec.tx_hash, rec.clone());
        }
        Self {
            engine_consumed: r.engine_consumed.iter().copied().collect(),
            runtime_consumed: r.runtime_consumed.iter().copied().collect(),
            produced,
            completed: r.completed.iter().copied().collect(),
            xpc,
        }
    }

    pub fn to_replay(&self) -> CrossShardReplaySnapshot {
        CrossShardReplaySnapshot {
            engine_consumed: self.engine_consumed.iter().copied().collect(),
            runtime_consumed: self.runtime_consumed.iter().copied().collect(),
            produced: self
                .produced
                .iter()
                .map(|(h, (tx, height))| (*h, tx.clone(), *height))
                .collect(),
            completed: self.completed.iter().copied().collect(),
            xpc: self.xpc.values().cloned().collect(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPqKeys {
    pub entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl CanonicalPqKeys {
    pub fn to_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalEvmBindings {
    pub by_evm: BTreeMap<[u8; 20], [u8; 32]>,
}

impl CanonicalEvmBindings {
    pub fn from_state(state: &EvmBindingsState) -> Self {
        Self {
            by_evm: state.by_evm.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }

    pub fn to_snapshot(&self) -> EvmBindingsSnapshot {
        EvmBindingsSnapshot {
            by_evm: self.by_evm.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }
}

/// Account bucket full-chunk payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountBucketFull {
    pub bucket: u8,
    pub sub_index: u16,
    pub total_sub_chunks: u16,
    pub accounts: Vec<AccountState>,
}

/// Account bucket incremental diff payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountBucketDelta {
    pub bucket: u8,
    pub expected_base_hash: [u8; 32],
    pub upserts: Vec<AccountState>,
    pub deletes: Vec<[u8; 32]>,
}

/// Generic sorted/unique map diff payload (`Tokens`, `Contracts`, `Orderbooks`, `OrderEscrow`, `PqKeys`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapDiff<K, V> {
    pub expected_base_hash: [u8; 32],
    pub upserts: Vec<(K, V)>,
    pub deletes: Vec<K>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokensDelta {
    pub next_nonce: u64,
    pub diff: MapDiff<[u8; 32], CanonicalTokenActor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractsDelta {
    pub next_nonce: u64,
    pub last_return_data: Vec<u8>,
    pub diff: MapDiff<[u8; 32], CanonicalContract>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardDelta {
    pub expected_base_hash: [u8; 32],
    pub engine_consumed_add: Vec<CrossShardKey>,
    pub engine_consumed_del: Vec<CrossShardKey>,
    pub runtime_consumed_add: Vec<CrossShardKey>,
    pub runtime_consumed_del: Vec<CrossShardKey>,
    pub produced_upserts: Vec<([u8; 32], Transaction, u64)>,
    pub produced_deletes: Vec<[u8; 32]>,
    pub completed_add: Vec<[u8; 32]>,
    pub completed_del: Vec<[u8; 32]>,
    pub xpc_upserts: Vec<XpcRecord>,
    pub xpc_deletes: Vec<[u8; 32]>,
}

// ============================================================================
// Canonical State Container (`SnapStateV4`)
// ============================================================================

/// Complete canonical state represented by `SnapV4`.
///
/// Explicitly excludes `safety_record_v1`, `ConsensusCheckpoint`, and `VoteWatermark`.
#[derive(Clone, Debug)]
pub struct SnapStateV4 {
    pub buckets: [Vec<AccountState>; N_ACCOUNT_BUCKETS],
    pub scalars: CanonicalScalars,
    pub tokens: CanonicalTokenRegistry,
    pub contracts: CanonicalContractRegistry,
    pub orderbooks: CanonicalOrderbookManager,
    pub pmm: CanonicalPmm,
    pub order_escrow: CanonicalOrderEscrow,
    pub staking: CanonicalStakingLedger,
    pub governance: CanonicalGovernance,
    pub oracle: OracleState,
    pub session_keys: SessionKeyRegistry,
    pub bridge: BridgeState,
    pub zkml_models: ZkMlModelRegistry,
    pub cross_shard: CanonicalCrossShard,
    pub cnvrf_v3: CnVrfV3EngineSnapshot,
    pub pq_keys: CanonicalPqKeys,
    pub evm_bindings: CanonicalEvmBindings,
}

impl Default for SnapStateV4 {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| Vec::new()),
            scalars: CanonicalScalars::default(),
            tokens: CanonicalTokenRegistry::default(),
            contracts: CanonicalContractRegistry::default(),
            orderbooks: CanonicalOrderbookManager::default(),
            pmm: CanonicalPmm::default(),
            order_escrow: CanonicalOrderEscrow::default(),
            staking: CanonicalStakingLedger::default(),
            governance: CanonicalGovernance::default(),
            oracle: OracleState::default(),
            session_keys: SessionKeyRegistry::default(),
            bridge: BridgeState::default(),
            zkml_models: ZkMlModelRegistry::default(),
            cross_shard: CanonicalCrossShard::default(),
            cnvrf_v3: CnVrfV3EngineSnapshot::default(),
            pq_keys: CanonicalPqKeys::default(),
            evm_bindings: CanonicalEvmBindings::default(),
        }
    }
}

impl PartialEq for SnapStateV4 {
    fn eq(&self, other: &Self) -> bool {
        let Ok(a_accounts) = encode_canonical(&self.buckets.iter().collect::<Vec<_>>()) else {
            return false;
        };
        let Ok(b_accounts) = encode_canonical(&other.buckets.iter().collect::<Vec<_>>()) else {
            return false;
        };
        if a_accounts != b_accounts || self.scalars != other.scalars {
            return false;
        }
        for domain in DomainUnitId::ALL {
            if domain == DomainUnitId::Scalars {
                continue;
            }
            let Ok(ha) = self.domain_state_hash(domain) else {
                return false;
            };
            let Ok(hb) = other.domain_state_hash(domain) else {
                return false;
            };
            if ha != hb {
                return false;
            }
        }
        true
    }
}

impl Eq for SnapStateV4 {}

impl SnapStateV4 {
    /// Capture a canonical `SnapStateV4` from an `InMemoryStateEngine`.
    ///
    /// Never reads `safety_record_v1`, `ConsensusCheckpoint`, or `VoteWatermark`.
    pub async fn capture_from_engine(
        engine: &InMemoryStateEngine,
        staking_override: Option<&StakingLedger>,
        governance_override: Option<&Governance>,
        pq_keys_override: Option<&[(Vec<u8>, Vec<u8>)]>,
    ) -> Result<Self, SnapV4Error> {
        let state_snap = engine.capture_state_snapshot().await;
        let staking_guard;
        let staking = match staking_override {
            Some(s) => s,
            None => {
                staking_guard = engine.staking_read().await;
                &staking_guard
            }
        };
        let gov_guard;
        let governance = match governance_override {
            Some(g) => g,
            None => {
                gov_guard = engine.governance_read().await;
                &gov_guard
            }
        };

        let domain_snap = DomainSnapshot::capture(engine, staking, governance).await;
        let session_keys = engine.session_keys_read().await.clone();
        let bridge = engine.bridge_read().await.clone();
        let zkml_models = engine.zkml_models_read().await.clone();
        let cnvrf_v3 = engine.cnvrf_v3_snapshot().await;
        let evm_bindings = CanonicalEvmBindings::from_state(&*engine.evm_bindings_read().await);

        let engine_consumed = engine.cross_shard_consumed_snapshot().await;
        let produced_pairs = engine.cross_shard_produced_snapshot().await;
        let completed = engine.cross_shard_completed_snapshot().await;
        let xpc = engine.xpc_snapshot().await;

        // Reconstruct `produced` transactions if xpc carries them, or synthesize placeholder-free
        // entries when only `(tx_hash, height)` exist; callers with full `CrossShardReplaySnapshot`
        // can also populate `cross_shard` directly.
        let mut produced_map = BTreeMap::new();
        for (tx_hash, height) in produced_pairs {
            if let Some(rec) = xpc.iter().find(|r| r.tx_hash == tx_hash) {
                produced_map.insert(tx_hash, (rec.tx.clone(), height));
            }
        }
        let cross_shard = CanonicalCrossShard {
            engine_consumed: engine_consumed.into_iter().collect(),
            runtime_consumed: BTreeSet::new(),
            produced: produced_map,
            completed: completed.into_iter().collect(),
            xpc: xpc.into_iter().map(|r| (r.tx_hash, r)).collect(),
        };

        let mut buckets: [Vec<AccountState>; N_ACCOUNT_BUCKETS] =
            std::array::from_fn(|_| Vec::new());
        for acc in state_snap.accounts {
            let b = acc.address[0] as usize;
            buckets[b].push(acc);
        }
        for (idx, bucket) in buckets.iter_mut().enumerate() {
            bucket.sort_by_key(|a| a.address);
            for w in bucket.windows(2) {
                if w[0].address == w[1].address {
                    return Err(SnapV4Error::UnsortedOrDuplicateAccount { bucket: idx as u8 });
                }
            }
        }

        let scalars = CanonicalScalars {
            penalty: state_snap.penalty.into_iter().collect(),
            total_minted_nano: state_snap.total_minted_nano,
        };

        let mut pq_entries = BTreeMap::new();
        if let Some(pairs) = pq_keys_override {
            for (k, v) in pairs {
                pq_entries.insert(k.clone(), v.clone());
            }
        } else {
            let tree_opt = engine
                .pq_tree
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(tree) = tree_opt {
                for kv in tree.iter() {
                    let (k, v) = kv.map_err(|e| SnapV4Error::PqKeyValidation(e.to_string()))?;
                    pq_entries.insert(k.to_vec(), v.to_vec());
                }
            } else {
                for bucket in &buckets {
                    for acc in bucket {
                        if acc.pubkey_hash.is_some() {
                            if let Some((scheme, pk, salt)) =
                                engine.get_pinned_pubkey_with_salt(&acc.address)
                            {
                                let mut a_key = Vec::with_capacity(34);
                                a_key.extend_from_slice(b"a:");
                                a_key.extend_from_slice(&acc.address);
                                let a_val = encode_canonical(&(scheme, &pk, salt))?;
                                pq_entries.insert(a_key, a_val);

                                let pk_hash = *blake3::hash(&pk).as_bytes();
                                let mut h_key = Vec::with_capacity(34);
                                h_key.extend_from_slice(b"h:");
                                h_key.extend_from_slice(&pk_hash);
                                pq_entries.insert(h_key, pk);
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            buckets,
            scalars,
            tokens: CanonicalTokenRegistry::from_registry(&domain_snap.tokens),
            contracts: CanonicalContractRegistry::from_registry(&domain_snap.contracts),
            orderbooks: CanonicalOrderbookManager::from_manager(&domain_snap.orderbooks),
            pmm: CanonicalPmm {
                pmm: domain_snap.pmm,
                pmm_usdt_token: domain_snap.pmm_usdt_token,
                pmm_treasury: domain_snap.pmm_treasury,
            },
            order_escrow: CanonicalOrderEscrow {
                escrow: domain_snap.order_escrow.into_iter().collect(),
            },
            staking: CanonicalStakingLedger::from_ledger(&domain_snap.staking),
            governance: CanonicalGovernance::from_governance(&domain_snap.governance),
            oracle: domain_snap.oracle,
            session_keys,
            bridge,
            zkml_models,
            cross_shard,
            cnvrf_v3,
            pq_keys: CanonicalPqKeys {
                entries: pq_entries,
            },
            evm_bindings,
        })
    }

    /// Install this `SnapStateV4` into a fresh or target `InMemoryStateEngine`.
    ///
    /// Never touches `safety_record_v1`, `ConsensusCheckpoint`, or `VoteWatermark`.
    pub async fn apply_to_engine(
        &self,
        engine: &InMemoryStateEngine,
    ) -> Result<(StakingLedger, Governance), SnapV4Error> {
        let mut all_accounts = Vec::new();
        for bucket in &self.buckets {
            all_accounts.extend(bucket.iter().cloned());
        }
        all_accounts.sort_by_key(|a| a.address);

        let v2 = StateSnapshotV2 {
            accounts: all_accounts,
            penalty: self.scalars.penalty.iter().map(|(k, v)| (*k, *v)).collect(),
            total_minted_nano: self.scalars.total_minted_nano,
        };
        let v2_bytes = encode_canonical(&v2)?;
        engine
            .restore_snapshot_preserve_replay_sets(&v2_bytes)
            .await
            .map_err(SnapV4Error::EngineRestore)?;

        let domain_snap = DomainSnapshot {
            tokens: self.tokens.to_registry(),
            contracts: self.contracts.to_registry(),
            orderbooks: self.orderbooks.to_manager(),
            pmm: self.pmm.pmm.clone(),
            pmm_usdt_token: self.pmm.pmm_usdt_token,
            pmm_treasury: self.pmm.pmm_treasury,
            order_escrow: self
                .order_escrow
                .escrow
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
            staking: self.staking.to_ledger(),
            governance: self.governance.to_governance(),
            oracle: self.oracle.clone(),
        };
        let (staking, governance) = domain_snap.apply(engine).await;

        let session_bytes = encode_canonical(&self.session_keys)?;
        engine
            .restore_session_keys(&session_bytes)
            .await
            .map_err(SnapV4Error::EngineRestore)?;

        let bridge_bytes = encode_canonical(&self.bridge)?;
        engine
            .restore_bridge(&bridge_bytes)
            .await
            .map_err(SnapV4Error::EngineRestore)?;

        let zkml_bytes = encode_canonical(&self.zkml_models)?;
        engine
            .restore_zkml_models(&zkml_bytes)
            .await
            .map_err(SnapV4Error::EngineRestore)?;

        let replay = self.cross_shard.to_replay();
        engine.restore_cross_shard_replay(&replay).await;

        engine.restore_cnvrf_v3_snapshot(&self.cnvrf_v3).await;

        let pq_pairs = self.pq_keys.to_pairs();
        let pq_bytes = encode_canonical(&pq_pairs)?;
        engine
            .restore_pq_keys(&pq_bytes)
            .await
            .map_err(SnapV4Error::EngineRestore)?;

        engine
            .restore_evm_bindings_state(self.evm_bindings.to_snapshot())
            .await
            .map_err(SnapV4Error::EngineRestore)?;

        Ok((staking, governance))
    }

    /// Compute the deterministic `PatriciaTrie` + commitment state root using a
    /// throwaway `InMemoryStateEngine` (zero mutation to any live engine or disk store).
    pub async fn compute_state_root(&self) -> Result<[u8; 32], SnapV4Error> {
        let throwaway = InMemoryStateEngine::new();
        self.apply_to_engine(&throwaway).await?;
        Ok(throwaway.get_state_root().await)
    }

    fn encode_bucket_full_chunks(&self, bucket: u8) -> Result<Vec<Vec<u8>>, SnapV4Error> {
        let accounts = &self.buckets[bucket as usize];
        if accounts.is_empty() {
            return Ok(Vec::new());
        }
        let mut slices: Vec<&[AccountState]> = Vec::new();
        let mut start = 0usize;
        while start < accounts.len() {
            let mut end = (start + MAX_ACCOUNTS_PER_CHUNK).min(accounts.len());
            // Shrink `end` if the serialized chunk would exceed MAX_SNAP_CHUNK_BYTES.
            loop {
                let probe = AccountBucketFull {
                    bucket,
                    sub_index: 0,
                    total_sub_chunks: 1,
                    accounts: accounts[start..end].to_vec(),
                };
                let len = encode_canonical(&probe)?.len();
                if len <= MAX_SNAP_CHUNK_BYTES {
                    break;
                }
                if end - start == 1 {
                    return Err(SnapV4Error::ChunkTooLarge {
                        len,
                        max: MAX_SNAP_CHUNK_BYTES,
                    });
                }
                end = start + (end - start) / 2;
            }
            slices.push(&accounts[start..end]);
            start = end;
        }
        let total_sub_chunks =
            u16::try_from(slices.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
        let mut out = Vec::with_capacity(slices.len());
        for (idx, slice) in slices.into_iter().enumerate() {
            let sub_index = u16::try_from(idx).map_err(|_| SnapV4Error::Overflow("sub_index"))?;
            let chunk = AccountBucketFull {
                bucket,
                sub_index,
                total_sub_chunks,
                accounts: slice.to_vec(),
            };
            let bytes = encode_canonical(&chunk)?;
            if bytes.len() > MAX_SNAP_CHUNK_BYTES {
                return Err(SnapV4Error::ChunkTooLarge {
                    len: bytes.len(),
                    max: MAX_SNAP_CHUNK_BYTES,
                });
            }
            out.push(bytes);
        }
        Ok(out)
    }

    pub fn bucket_state_hash(&self, bucket: u8) -> Result<[u8; 32], SnapV4Error> {
        let chunks = self.encode_bucket_full_chunks(bucket)?;
        if chunks.is_empty() {
            return Ok(empty_bucket_hash());
        }
        if chunks.len() == 1 {
            return Ok(compute_unit_hash(bucket as u16, 0, &chunks[0]));
        }
        let total =
            u16::try_from(chunks.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(SNAP_BUCKET_MULTI_DOMAIN);
        hasher.update(&[bucket]);
        hasher.update(&total.to_le_bytes());
        for (idx, raw) in chunks.iter().enumerate() {
            let sub_index = u16::try_from(idx).map_err(|_| SnapV4Error::Overflow("sub_index"))?;
            hasher.update(&compute_unit_hash(bucket as u16, sub_index, raw));
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn encode_tokens_full_chunks(&self) -> Result<Vec<Vec<u8>>, SnapV4Error> {
        let entries: Vec<&CanonicalTokenActor> = self.tokens.tokens.values().collect();
        if entries.is_empty() {
            let chunk = TokenChunk {
                sub_index: 0,
                total_sub_chunks: 1,
                next_nonce: self.tokens.next_nonce,
                entries: Vec::new(),
            };
            let bytes = encode_canonical(&chunk)?;
            if bytes.len() > MAX_SNAP_CHUNK_BYTES {
                return Err(SnapV4Error::ChunkTooLarge {
                    len: bytes.len(),
                    max: MAX_SNAP_CHUNK_BYTES,
                });
            }
            return Ok(vec![bytes]);
        }
        let mut slices: Vec<Vec<CanonicalTokenActor>> = Vec::new();
        let mut start = 0usize;
        while start < entries.len() {
            let mut end = entries.len();
            loop {
                let slice: Vec<CanonicalTokenActor> =
                    entries[start..end].iter().map(|e| (*e).clone()).collect();
                let probe = TokenChunk {
                    sub_index: 0,
                    total_sub_chunks: 1,
                    next_nonce: self.tokens.next_nonce,
                    entries: slice.clone(),
                };
                let len = encode_canonical(&probe)?.len();
                if len <= MAX_SNAP_CHUNK_BYTES {
                    slices.push(slice);
                    break;
                }
                if end - start == 1 {
                    return Err(SnapV4Error::ChunkTooLarge {
                        len,
                        max: MAX_SNAP_CHUNK_BYTES,
                    });
                }
                end = start + (end - start) / 2;
            }
            start = end;
        }
        let total_sub_chunks =
            u16::try_from(slices.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
        let mut out = Vec::with_capacity(slices.len());
        for (idx, slice) in slices.into_iter().enumerate() {
            let sub_index = u16::try_from(idx).map_err(|_| SnapV4Error::Overflow("sub_index"))?;
            let chunk = TokenChunk {
                sub_index,
                total_sub_chunks,
                next_nonce: self.tokens.next_nonce,
                entries: slice,
            };
            let bytes = encode_canonical(&chunk)?;
            if bytes.len() > MAX_SNAP_CHUNK_BYTES {
                return Err(SnapV4Error::ChunkTooLarge {
                    len: bytes.len(),
                    max: MAX_SNAP_CHUNK_BYTES,
                });
            }
            out.push(bytes);
        }
        Ok(out)
    }

    fn encode_contracts_full_chunks(&self) -> Result<Vec<Vec<u8>>, SnapV4Error> {
        let entries: Vec<&CanonicalContract> = self.contracts.contracts.values().collect();
        if entries.is_empty() {
            let chunk = ContractChunk {
                sub_index: 0,
                total_sub_chunks: 1,
                next_nonce: self.contracts.next_nonce,
                last_return_data: self.contracts.last_return_data.clone(),
                entries: Vec::new(),
            };
            let bytes = encode_canonical(&chunk)?;
            if bytes.len() > MAX_SNAP_CHUNK_BYTES {
                return Err(SnapV4Error::ChunkTooLarge {
                    len: bytes.len(),
                    max: MAX_SNAP_CHUNK_BYTES,
                });
            }
            return Ok(vec![bytes]);
        }
        let mut slices: Vec<Vec<CanonicalContract>> = Vec::new();
        let mut start = 0usize;
        while start < entries.len() {
            let mut end = entries.len();
            loop {
                let slice: Vec<CanonicalContract> =
                    entries[start..end].iter().map(|e| (*e).clone()).collect();
                let probe = ContractChunk {
                    sub_index: 0,
                    total_sub_chunks: 1,
                    next_nonce: self.contracts.next_nonce,
                    last_return_data: if start == 0 {
                        self.contracts.last_return_data.clone()
                    } else {
                        Vec::new()
                    },
                    entries: slice.clone(),
                };
                let len = encode_canonical(&probe)?.len();
                if len <= MAX_SNAP_CHUNK_BYTES {
                    slices.push(slice);
                    break;
                }
                if end - start == 1 {
                    return Err(SnapV4Error::ChunkTooLarge {
                        len,
                        max: MAX_SNAP_CHUNK_BYTES,
                    });
                }
                end = start + (end - start) / 2;
            }
            start = end;
        }
        let total_sub_chunks =
            u16::try_from(slices.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
        let mut out = Vec::with_capacity(slices.len());
        for (idx, slice) in slices.into_iter().enumerate() {
            let sub_index = u16::try_from(idx).map_err(|_| SnapV4Error::Overflow("sub_index"))?;
            let chunk = ContractChunk {
                sub_index,
                total_sub_chunks,
                next_nonce: self.contracts.next_nonce,
                last_return_data: if idx == 0 {
                    self.contracts.last_return_data.clone()
                } else {
                    Vec::new()
                },
                entries: slice,
            };
            let bytes = encode_canonical(&chunk)?;
            if bytes.len() > MAX_SNAP_CHUNK_BYTES {
                return Err(SnapV4Error::ChunkTooLarge {
                    len: bytes.len(),
                    max: MAX_SNAP_CHUNK_BYTES,
                });
            }
            out.push(bytes);
        }
        Ok(out)
    }

    fn encode_domain_full_chunks(&self, domain: DomainUnitId) -> Result<Vec<Vec<u8>>, SnapV4Error> {
        let single = match domain {
            DomainUnitId::Scalars => encode_canonical(&self.scalars)?,
            DomainUnitId::Tokens => return self.encode_tokens_full_chunks(),
            DomainUnitId::Contracts => return self.encode_contracts_full_chunks(),
            DomainUnitId::Orderbooks => encode_canonical(&self.orderbooks)?,
            DomainUnitId::Pmm => encode_canonical(&self.pmm)?,
            DomainUnitId::OrderEscrow => encode_canonical(&self.order_escrow)?,
            DomainUnitId::Staking => encode_canonical(&self.staking)?,
            DomainUnitId::Governance => encode_canonical(&self.governance)?,
            DomainUnitId::Oracle => encode_canonical(&self.oracle)?,
            DomainUnitId::SessionKeys => encode_canonical(&self.session_keys)?,
            DomainUnitId::Bridge => encode_canonical(&self.bridge)?,
            DomainUnitId::ZkMl => encode_canonical(&self.zkml_models)?,
            DomainUnitId::CrossShard => encode_canonical(&self.cross_shard)?,
            DomainUnitId::CnVrfV3 => encode_canonical(&self.cnvrf_v3)?,
            DomainUnitId::PqKeys => encode_canonical(&self.pq_keys)?,
            DomainUnitId::EvmBindings => encode_canonical(&self.evm_bindings)?,
        };
        if single.len() > MAX_SNAP_CHUNK_BYTES {
            return Err(SnapV4Error::ChunkTooLarge {
                len: single.len(),
                max: MAX_SNAP_CHUNK_BYTES,
            });
        }
        Ok(vec![single])
    }

    pub fn domain_state_hash(&self, domain: DomainUnitId) -> Result<[u8; 32], SnapV4Error> {
        let chunks = self.encode_domain_full_chunks(domain)?;
        if chunks.len() == 1 {
            return Ok(compute_unit_hash(domain.tag(), 0, &chunks[0]));
        }
        let total =
            u16::try_from(chunks.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(SNAP_DOMAIN_MULTI_DOMAIN);
        hasher.update(&domain.tag().to_le_bytes());
        hasher.update(&total.to_le_bytes());
        for (idx, raw) in chunks.iter().enumerate() {
            let sub_index = u16::try_from(idx).map_err(|_| SnapV4Error::Overflow("sub_index"))?;
            hasher.update(&compute_unit_hash(domain.tag(), sub_index, raw));
        }
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn unit_state_hash(&self, unit_tag: u16) -> Result<[u8; 32], SnapV4Error> {
        match UnitKind::from_tag(unit_tag) {
            Some(UnitKind::AccountBucket(b)) => self.bucket_state_hash(b),
            Some(UnitKind::Domain(d)) => self.domain_state_hash(d),
            None => Err(SnapV4Error::UnknownUnitTag(unit_tag)),
        }
    }
}

// ============================================================================
// Snapshot Builder (`Base` and `Delta`)
// ============================================================================

#[derive(Clone, Debug)]
pub struct SnapshotBuildParams<'a> {
    pub chain_id: u64,
    pub shard_id: u32,
    pub target_height: u64,
    pub target_block_hash: [u8; 32],
    pub target_state_root: [u8; 32],
    pub validator_set: &'a ValidatorSet,
}

#[derive(Clone, Debug)]
pub struct EncodedSnapshotV4 {
    pub manifest: SnapshotManifestV1,
    pub chunks: BTreeMap<(u16, u16), Vec<u8>>,
}

fn push_full_chunks(
    unit_tag: u16,
    raw_chunks: Vec<Vec<u8>>,
    units: &mut Vec<SnapshotUnitDesc>,
    chunks_map: &mut BTreeMap<(u16, u16), Vec<u8>>,
    total_wire_bytes: &mut u64,
) -> Result<(), SnapV4Error> {
    for (idx, raw) in raw_chunks.into_iter().enumerate() {
        let sub_index = u16::try_from(idx).map_err(|_| SnapV4Error::Overflow("sub_index"))?;
        if raw.is_empty() {
            return Err(SnapV4Error::ZeroLenNonUnchangedChunk {
                unit_tag,
                sub_index,
            });
        }
        if raw.len() > MAX_SNAP_CHUNK_BYTES {
            return Err(SnapV4Error::ChunkTooLarge {
                len: raw.len(),
                max: MAX_SNAP_CHUNK_BYTES,
            });
        }
        let byte_len = u32::try_from(raw.len()).map_err(|_| SnapV4Error::Overflow("byte_len"))?;
        let chunk_hash = *blake3::hash(&raw).as_bytes();
        let unit_hash = compute_unit_hash(unit_tag, sub_index, &raw);
        *total_wire_bytes = total_wire_bytes
            .checked_add(byte_len as u64)
            .ok_or(SnapV4Error::Overflow("total_wire_bytes"))?;
        units.push(SnapshotUnitDesc {
            unit_tag,
            sub_index,
            encoding: UNIT_ENC_FULL,
            unit_hash,
            chunk_hash,
            byte_len,
        });
        chunks_map.insert((unit_tag, sub_index), raw);
    }
    Ok(())
}

fn push_unchanged(
    unit_tag: u16,
    unit_hash: [u8; 32],
    units: &mut Vec<SnapshotUnitDesc>,
) -> Result<(), SnapV4Error> {
    units.push(SnapshotUnitDesc {
        unit_tag,
        sub_index: 0,
        encoding: UNIT_ENC_UNCHANGED,
        unit_hash,
        chunk_hash: [0u8; 32],
        byte_len: 0,
    });
    Ok(())
}

fn push_delta_or_full(
    unit_tag: u16,
    target_hash: [u8; 32],
    delta_bytes: Vec<u8>,
    full_chunks: Vec<Vec<u8>>,
    units: &mut Vec<SnapshotUnitDesc>,
    chunks_map: &mut BTreeMap<(u16, u16), Vec<u8>>,
    total_wire_bytes: &mut u64,
) -> Result<(), SnapV4Error> {
    let full_total: usize = full_chunks.iter().map(|c| c.len()).sum();
    let delta_fits = delta_bytes.len() <= MAX_SNAP_CHUNK_BYTES
        && delta_bytes
            .len()
            .checked_mul(DELTA_FULL_THRESHOLD_DEN)
            .is_some_and(|lhs| {
                full_total
                    .checked_mul(DELTA_FULL_THRESHOLD_NUM)
                    .is_some_and(|rhs| lhs < rhs)
            });
    if delta_fits && !delta_bytes.is_empty() {
        let byte_len =
            u32::try_from(delta_bytes.len()).map_err(|_| SnapV4Error::Overflow("byte_len"))?;
        let chunk_hash = *blake3::hash(&delta_bytes).as_bytes();
        *total_wire_bytes = total_wire_bytes
            .checked_add(byte_len as u64)
            .ok_or(SnapV4Error::Overflow("total_wire_bytes"))?;
        units.push(SnapshotUnitDesc {
            unit_tag,
            sub_index: 0,
            encoding: UNIT_ENC_DELTA,
            unit_hash: target_hash,
            chunk_hash,
            byte_len,
        });
        chunks_map.insert((unit_tag, 0), delta_bytes);
        Ok(())
    } else {
        push_full_chunks(unit_tag, full_chunks, units, chunks_map, total_wire_bytes)
    }
}

fn finalize_manifest(
    kind: SnapshotKind,
    params: &SnapshotBuildParams<'_>,
    units: Vec<SnapshotUnitDesc>,
    total_wire_bytes: u64,
    keypair: &FalconKeypair,
) -> Result<SnapshotManifestV1, SnapV4Error> {
    if params.validator_set.validators.is_empty() {
        return Err(SnapV4Error::EmptyValidatorSet);
    }
    if units.len() > MAX_SNAP_UNITS {
        return Err(SnapV4Error::TooManyUnits {
            count: units.len(),
            max: MAX_SNAP_UNITS,
        });
    }
    if total_wire_bytes > MAX_SNAP_WIRE_BYTES {
        return Err(SnapV4Error::WireBytesLimitExceeded {
            bytes: total_wire_bytes,
            max: MAX_SNAP_WIRE_BYTES,
        });
    }
    if total_wire_bytes > MAX_SNAPSHOT_DECODE_BYTES {
        return Err(SnapV4Error::DecodeBytesLimitExceeded {
            bytes: total_wire_bytes,
            max: MAX_SNAPSHOT_DECODE_BYTES,
        });
    }
    let units_merkle_root = compute_units_merkle_root(&units);
    let mut manifest = SnapshotManifestV1 {
        magic: SNAP_MANIFEST_MAGIC,
        version: SNAP_MANIFEST_VERSION,
        chain_id: params.chain_id,
        shard_id: params.shard_id,
        kind,
        target_height: params.target_height,
        target_block_hash: params.target_block_hash,
        target_state_root: params.target_state_root,
        validator_set_hash: canonical_vset_hash(params.validator_set),
        total_wire_bytes,
        total_uncompressed_bytes: total_wire_bytes,
        units_merkle_root,
        units,
        publisher_id: keypair.validator_id(),
        publisher_sig: Vec::new(),
    };
    sign_manifest(&mut manifest, keypair)?;
    Ok(manifest)
}

/// Build a `Base` `SnapV4` checkpoint (256 prefix buckets + 16 canonical domain units).
pub fn build_base_snapshot(
    state: &SnapStateV4,
    params: &SnapshotBuildParams<'_>,
    keypair: &FalconKeypair,
) -> Result<EncodedSnapshotV4, SnapV4Error> {
    let mut units = Vec::with_capacity(TOTAL_UNIT_TAGS);
    let mut chunks = BTreeMap::new();
    let mut total_wire_bytes: u64 = 0;

    for b in 0..N_ACCOUNT_BUCKETS {
        let bucket = b as u8;
        let bucket_chunks = state.encode_bucket_full_chunks(bucket)?;
        if bucket_chunks.is_empty() {
            push_unchanged(bucket as u16, empty_bucket_hash(), &mut units)?;
        } else {
            push_full_chunks(
                bucket as u16,
                bucket_chunks,
                &mut units,
                &mut chunks,
                &mut total_wire_bytes,
            )?;
        }
    }

    for domain in DomainUnitId::ALL {
        let domain_chunks = state.encode_domain_full_chunks(domain)?;
        push_full_chunks(
            domain.tag(),
            domain_chunks,
            &mut units,
            &mut chunks,
            &mut total_wire_bytes,
        )?;
    }

    let manifest = finalize_manifest(SnapshotKind::Base, params, units, total_wire_bytes, keypair)?;
    Ok(EncodedSnapshotV4 { manifest, chunks })
}

fn build_map_diff<K, V>(
    expected_base_hash: [u8; 32],
    base: &BTreeMap<K, V>,
    target: &BTreeMap<K, V>,
) -> Result<MapDiff<K, V>, SnapV4Error>
where
    K: Ord + Clone,
    V: Serialize + Clone,
{
    let mut upserts = Vec::new();
    let mut deletes = Vec::new();
    for k in base.keys() {
        if !target.contains_key(k) {
            deletes.push(k.clone());
        }
    }
    for (k, tv) in target {
        match base.get(k) {
            None => upserts.push((k.clone(), tv.clone())),
            Some(bv) => {
                if encode_canonical(bv)? != encode_canonical(tv)? {
                    upserts.push((k.clone(), tv.clone()));
                }
            }
        }
    }
    Ok(MapDiff {
        expected_base_hash,
        upserts,
        deletes,
    })
}

/// Build an incremental `Delta` `SnapV4` checkpoint (`base -> target`).
pub fn build_delta_snapshot(
    base: &SnapStateV4,
    target: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    params: &SnapshotBuildParams<'_>,
    keypair: &FalconKeypair,
) -> Result<EncodedSnapshotV4, SnapV4Error> {
    if base_height >= params.target_height {
        return Err(SnapV4Error::NonMonotonicDeltaChain {
            prev_height: base_height,
            next_height: params.target_height,
        });
    }

    let mut units = Vec::with_capacity(TOTAL_UNIT_TAGS);
    let mut chunks = BTreeMap::new();
    let mut total_wire_bytes: u64 = 0;

    // 256 account buckets
    for b in 0..N_ACCOUNT_BUCKETS {
        let bucket = b as u8;
        let base_hash = base.bucket_state_hash(bucket)?;
        let target_hash = target.bucket_state_hash(bucket)?;
        if base_hash == target_hash {
            push_unchanged(bucket as u16, target_hash, &mut units)?;
            continue;
        }
        let base_map: BTreeMap<[u8; 32], &AccountState> =
            base.buckets[b].iter().map(|a| (a.address, a)).collect();
        let target_map: BTreeMap<[u8; 32], &AccountState> =
            target.buckets[b].iter().map(|a| (a.address, a)).collect();
        let mut deletes = Vec::new();
        for addr in base_map.keys() {
            if !target_map.contains_key(addr) {
                deletes.push(*addr);
            }
        }
        let mut upserts = Vec::new();
        for (addr, t_acc) in &target_map {
            match base_map.get(addr) {
                None => upserts.push((*t_acc).clone()),
                Some(b_acc) => {
                    if encode_canonical(*b_acc)? != encode_canonical(*t_acc)? {
                        upserts.push((*t_acc).clone());
                    }
                }
            }
        }
        let delta = AccountBucketDelta {
            bucket,
            expected_base_hash: base_hash,
            upserts,
            deletes,
        };
        let delta_bytes = encode_canonical(&delta)?;
        let full_chunks = if target.buckets[b].is_empty() {
            vec![encode_canonical(&AccountBucketFull {
                bucket,
                sub_index: 0,
                total_sub_chunks: 1,
                accounts: Vec::new(),
            })?]
        } else {
            target.encode_bucket_full_chunks(bucket)?
        };
        push_delta_or_full(
            bucket as u16,
            target_hash,
            delta_bytes,
            full_chunks,
            &mut units,
            &mut chunks,
            &mut total_wire_bytes,
        )?;
    }

    // 16 domain units
    for domain in DomainUnitId::ALL {
        let base_hash = base.domain_state_hash(domain)?;
        let target_hash = target.domain_state_hash(domain)?;
        if base_hash == target_hash {
            push_unchanged(domain.tag(), target_hash, &mut units)?;
            continue;
        }
        let full_chunks = target.encode_domain_full_chunks(domain)?;
        match domain {
            DomainUnitId::Scalars => {
                let diff =
                    build_map_diff(base_hash, &base.scalars.penalty, &target.scalars.penalty)?;
                let delta = ScalarsDelta {
                    expected_base_hash: base_hash,
                    penalty_upserts: diff.upserts,
                    penalty_deletes: diff.deletes,
                    total_minted_nano: target.scalars.total_minted_nano,
                };
                let delta_bytes = encode_canonical(&delta)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::Tokens => {
                let diff = build_map_diff(base_hash, &base.tokens.tokens, &target.tokens.tokens)?;
                let delta = TokensDelta {
                    next_nonce: target.tokens.next_nonce,
                    diff,
                };
                let delta_bytes = encode_canonical(&delta)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::Contracts => {
                let diff = build_map_diff(
                    base_hash,
                    &base.contracts.contracts,
                    &target.contracts.contracts,
                )?;
                let delta = ContractsDelta {
                    next_nonce: target.contracts.next_nonce,
                    last_return_data: target.contracts.last_return_data.clone(),
                    diff,
                };
                let delta_bytes = encode_canonical(&delta)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::Orderbooks => {
                let diff =
                    build_map_diff(base_hash, &base.orderbooks.books, &target.orderbooks.books)?;
                let delta_bytes = encode_canonical(&diff)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::OrderEscrow => {
                let diff = build_map_diff(
                    base_hash,
                    &base.order_escrow.escrow,
                    &target.order_escrow.escrow,
                )?;
                let delta_bytes = encode_canonical(&diff)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::PqKeys => {
                let diff =
                    build_map_diff(base_hash, &base.pq_keys.entries, &target.pq_keys.entries)?;
                let delta_bytes = encode_canonical(&diff)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::EvmBindings => {
                let diff = build_map_diff(
                    base_hash,
                    &base.evm_bindings.by_evm,
                    &target.evm_bindings.by_evm,
                )?;
                let delta_bytes = encode_canonical(&diff)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::CrossShard => {
                let engine_consumed_add: Vec<CrossShardKey> = target
                    .cross_shard
                    .engine_consumed
                    .difference(&base.cross_shard.engine_consumed)
                    .copied()
                    .collect();
                let engine_consumed_del: Vec<CrossShardKey> = base
                    .cross_shard
                    .engine_consumed
                    .difference(&target.cross_shard.engine_consumed)
                    .copied()
                    .collect();
                let runtime_consumed_add: Vec<CrossShardKey> = target
                    .cross_shard
                    .runtime_consumed
                    .difference(&base.cross_shard.runtime_consumed)
                    .copied()
                    .collect();
                let runtime_consumed_del: Vec<CrossShardKey> = base
                    .cross_shard
                    .runtime_consumed
                    .difference(&target.cross_shard.runtime_consumed)
                    .copied()
                    .collect();
                let mut produced_upserts = Vec::new();
                let mut produced_deletes = Vec::new();
                for k in base.cross_shard.produced.keys() {
                    if !target.cross_shard.produced.contains_key(k) {
                        produced_deletes.push(*k);
                    }
                }
                for (k, tv) in &target.cross_shard.produced {
                    match base.cross_shard.produced.get(k) {
                        None => produced_upserts.push((*k, tv.0.clone(), tv.1)),
                        Some(bv) => {
                            if encode_canonical(bv)? != encode_canonical(tv)? {
                                produced_upserts.push((*k, tv.0.clone(), tv.1));
                            }
                        }
                    }
                }
                let completed_add: Vec<[u8; 32]> = target
                    .cross_shard
                    .completed
                    .difference(&base.cross_shard.completed)
                    .copied()
                    .collect();
                let completed_del: Vec<[u8; 32]> = base
                    .cross_shard
                    .completed
                    .difference(&target.cross_shard.completed)
                    .copied()
                    .collect();
                let xpc_diff =
                    build_map_diff(base_hash, &base.cross_shard.xpc, &target.cross_shard.xpc)?;
                let delta = CrossShardDelta {
                    expected_base_hash: base_hash,
                    engine_consumed_add,
                    engine_consumed_del,
                    runtime_consumed_add,
                    runtime_consumed_del,
                    produced_upserts,
                    produced_deletes,
                    completed_add,
                    completed_del,
                    xpc_upserts: xpc_diff.upserts.into_iter().map(|(_, v)| v).collect(),
                    xpc_deletes: xpc_diff.deletes,
                };
                let delta_bytes = encode_canonical(&delta)?;
                push_delta_or_full(
                    domain.tag(),
                    target_hash,
                    delta_bytes,
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
            DomainUnitId::Pmm
            | DomainUnitId::Staking
            | DomainUnitId::Governance
            | DomainUnitId::Oracle
            | DomainUnitId::SessionKeys
            | DomainUnitId::Bridge
            | DomainUnitId::ZkMl
            | DomainUnitId::CnVrfV3 => {
                push_full_chunks(
                    domain.tag(),
                    full_chunks,
                    &mut units,
                    &mut chunks,
                    &mut total_wire_bytes,
                )?;
            }
        }
    }

    let manifest = finalize_manifest(
        SnapshotKind::Delta {
            base_height,
            base_state_root,
        },
        params,
        units,
        total_wire_bytes,
        keypair,
    )?;
    Ok(EncodedSnapshotV4 { manifest, chunks })
}

// ============================================================================
// Chunk Verification & Strict Application (`Base` + `Delta` + `DeltaChain`)
// ============================================================================

/// Verify a single received wire chunk against its `SnapshotUnitDesc` BEFORE buffering.
pub fn verify_unit_chunk(desc: &SnapshotUnitDesc, bytes: &[u8]) -> Result<(), SnapV4Error> {
    if desc.encoding == UNIT_ENC_UNCHANGED {
        return Err(SnapV4Error::UnexpectedChunk {
            unit_tag: desc.unit_tag,
            sub_index: desc.sub_index,
        });
    }
    if bytes.len() > MAX_SNAP_CHUNK_BYTES {
        return Err(SnapV4Error::ChunkTooLarge {
            len: bytes.len(),
            max: MAX_SNAP_CHUNK_BYTES,
        });
    }
    if bytes.len() != desc.byte_len as usize {
        return Err(SnapV4Error::ChunkByteLenMismatch {
            unit_tag: desc.unit_tag,
            sub_index: desc.sub_index,
            expected: desc.byte_len as usize,
            actual: bytes.len(),
        });
    }
    if *blake3::hash(bytes).as_bytes() != desc.chunk_hash {
        return Err(SnapV4Error::ChunkHashMismatch {
            unit_tag: desc.unit_tag,
            sub_index: desc.sub_index,
        });
    }
    if desc.encoding == UNIT_ENC_FULL {
        let computed_unit_hash = compute_unit_hash(desc.unit_tag, desc.sub_index, bytes);
        if computed_unit_hash != desc.unit_hash {
            return Err(SnapV4Error::UnitHashMismatch {
                unit_tag: desc.unit_tag,
                sub_index: desc.sub_index,
            });
        }
    }
    Ok(())
}

fn verify_strict_sorted_unique<K: Ord>(
    keys: &[K],
    domain: &'static str,
) -> Result<(), SnapV4Error> {
    for w in keys.windows(2) {
        if w[0] >= w[1] {
            return Err(SnapV4Error::UnsortedOrDuplicateKey { domain });
        }
    }
    Ok(())
}

fn verify_strict_sorted_unique_pairs<K: Ord, V>(
    pairs: &[(K, V)],
    domain: &'static str,
) -> Result<(), SnapV4Error> {
    for w in pairs.windows(2) {
        if w[0].0 >= w[1].0 {
            return Err(SnapV4Error::UnsortedOrDuplicateKey { domain });
        }
    }
    Ok(())
}

fn apply_map_diff<K, V>(
    map: &mut BTreeMap<K, V>,
    diff: MapDiff<K, V>,
    expected_base_hash: [u8; 32],
    domain: &'static str,
) -> Result<(), SnapV4Error>
where
    K: Ord + Clone,
{
    if diff.expected_base_hash != expected_base_hash {
        return Err(SnapV4Error::DeltaBaseUnitHashMismatch { unit_tag: 0 });
    }
    verify_strict_sorted_unique_pairs(&diff.upserts, domain)?;
    verify_strict_sorted_unique(&diff.deletes, domain)?;
    let del_set: BTreeSet<&K> = diff.deletes.iter().collect();
    for (k, _) in &diff.upserts {
        if del_set.contains(k) {
            return Err(SnapV4Error::UpsertDeleteOverlap { domain });
        }
    }
    for k in &diff.deletes {
        if map.remove(k).is_none() {
            return Err(SnapV4Error::DeleteMissingKey { domain });
        }
    }
    for (k, v) in diff.upserts {
        map.insert(k, v);
    }
    Ok(())
}

fn decode_bucket_full_chunks(
    bucket: u8,
    descs: &[&SnapshotUnitDesc],
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<Vec<AccountState>, SnapV4Error> {
    let mut assembled = Vec::new();
    let expected_total =
        u16::try_from(descs.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
    let mut prev_addr: Option<[u8; 32]> = None;

    for (idx, desc) in descs.iter().enumerate() {
        let raw =
            chunks
                .get(&(desc.unit_tag, desc.sub_index))
                .ok_or(SnapV4Error::MissingChunk {
                    unit_tag: desc.unit_tag,
                    sub_index: desc.sub_index,
                })?;
        verify_unit_chunk(desc, raw)?;
        let parsed: AccountBucketFull = decode_canonical_exact(raw, MAX_SNAP_CHUNK_BYTES as u64)?;
        if parsed.bucket != bucket {
            return Err(SnapV4Error::BucketMismatch {
                expected: bucket,
                got: parsed.bucket,
            });
        }
        if parsed.sub_index != idx as u16 {
            return Err(SnapV4Error::NonContiguousSubIndex {
                unit_tag: desc.unit_tag,
                expected: idx as u16,
                got: parsed.sub_index,
            });
        }
        if parsed.total_sub_chunks != expected_total {
            return Err(SnapV4Error::SubChunkCountMismatch {
                unit_tag: desc.unit_tag,
                expected: expected_total,
                got: parsed.total_sub_chunks,
            });
        }
        if parsed.accounts.len() > MAX_ACCOUNTS_PER_CHUNK {
            return Err(SnapV4Error::TooManyAccountsInChunk {
                bucket,
                count: parsed.accounts.len(),
                max: MAX_ACCOUNTS_PER_CHUNK,
            });
        }
        for acc in parsed.accounts {
            if acc.address[0] != bucket {
                return Err(SnapV4Error::WrongBucketAddress {
                    bucket,
                    addr_first_byte: acc.address[0],
                });
            }
            if let Some(prev) = prev_addr {
                if acc.address <= prev {
                    return Err(SnapV4Error::UnsortedOrDuplicateAccount { bucket });
                }
            }
            prev_addr = Some(acc.address);
            assembled.push(acc);
        }
    }
    Ok(assembled)
}

fn decode_tokens_full_chunks(
    descs: &[&SnapshotUnitDesc],
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<CanonicalTokenRegistry, SnapV4Error> {
    let expected_total =
        u16::try_from(descs.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
    let mut tokens = BTreeMap::new();
    let mut next_nonce = 0u64;
    let mut prev_id: Option<[u8; 32]> = None;

    for (idx, desc) in descs.iter().enumerate() {
        let raw =
            chunks
                .get(&(desc.unit_tag, desc.sub_index))
                .ok_or(SnapV4Error::MissingChunk {
                    unit_tag: desc.unit_tag,
                    sub_index: desc.sub_index,
                })?;
        verify_unit_chunk(desc, raw)?;
        let parsed: TokenChunk = decode_canonical_exact(raw, MAX_SNAP_CHUNK_BYTES as u64)?;
        if parsed.sub_index != idx as u16 {
            return Err(SnapV4Error::NonContiguousSubIndex {
                unit_tag: desc.unit_tag,
                expected: idx as u16,
                got: parsed.sub_index,
            });
        }
        if parsed.total_sub_chunks != expected_total {
            return Err(SnapV4Error::SubChunkCountMismatch {
                unit_tag: desc.unit_tag,
                expected: expected_total,
                got: parsed.total_sub_chunks,
            });
        }
        if idx == 0 {
            next_nonce = parsed.next_nonce;
        }
        for entry in parsed.entries {
            if let Some(prev) = prev_id {
                if entry.id <= prev {
                    return Err(SnapV4Error::UnsortedOrDuplicateKey { domain: "Tokens" });
                }
            }
            prev_id = Some(entry.id);
            tokens.insert(entry.id, entry);
        }
    }
    Ok(CanonicalTokenRegistry { tokens, next_nonce })
}

fn decode_contracts_full_chunks(
    descs: &[&SnapshotUnitDesc],
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<CanonicalContractRegistry, SnapV4Error> {
    let expected_total =
        u16::try_from(descs.len()).map_err(|_| SnapV4Error::Overflow("total_sub_chunks"))?;
    let mut contracts = BTreeMap::new();
    let mut next_nonce = 0u64;
    let mut last_return_data = Vec::new();
    let mut prev_addr: Option<[u8; 32]> = None;

    for (idx, desc) in descs.iter().enumerate() {
        let raw =
            chunks
                .get(&(desc.unit_tag, desc.sub_index))
                .ok_or(SnapV4Error::MissingChunk {
                    unit_tag: desc.unit_tag,
                    sub_index: desc.sub_index,
                })?;
        verify_unit_chunk(desc, raw)?;
        let parsed: ContractChunk = decode_canonical_exact(raw, MAX_SNAP_CHUNK_BYTES as u64)?;
        if parsed.sub_index != idx as u16 {
            return Err(SnapV4Error::NonContiguousSubIndex {
                unit_tag: desc.unit_tag,
                expected: idx as u16,
                got: parsed.sub_index,
            });
        }
        if parsed.total_sub_chunks != expected_total {
            return Err(SnapV4Error::SubChunkCountMismatch {
                unit_tag: desc.unit_tag,
                expected: expected_total,
                got: parsed.total_sub_chunks,
            });
        }
        if idx == 0 {
            next_nonce = parsed.next_nonce;
            last_return_data = parsed.last_return_data;
        }
        for entry in parsed.entries {
            if let Some(prev) = prev_addr {
                if entry.address <= prev {
                    return Err(SnapV4Error::UnsortedOrDuplicateKey {
                        domain: "Contracts",
                    });
                }
            }
            prev_addr = Some(entry.address);
            contracts.insert(entry.address, entry);
        }
    }
    Ok(CanonicalContractRegistry {
        contracts,
        next_nonce,
        last_return_data,
    })
}

fn check_no_unexpected_chunks(
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<(), SnapV4Error> {
    let expected_keys: BTreeSet<(u16, u16)> = manifest
        .units
        .iter()
        .filter(|d| d.encoding != UNIT_ENC_UNCHANGED)
        .map(|d| (d.unit_tag, d.sub_index))
        .collect();
    for &(tag, sub) in chunks.keys() {
        if !expected_keys.contains(&(tag, sub)) {
            return Err(SnapV4Error::UnexpectedChunk {
                unit_tag: tag,
                sub_index: sub,
            });
        }
    }
    Ok(())
}

fn group_units_by_tag(manifest: &SnapshotManifestV1) -> [Vec<&SnapshotUnitDesc>; TOTAL_UNIT_TAGS] {
    let mut grouped: [Vec<&SnapshotUnitDesc>; TOTAL_UNIT_TAGS] =
        std::array::from_fn(|_| Vec::new());
    for desc in &manifest.units {
        grouped[desc.unit_tag as usize].push(desc);
    }
    grouped
}

/// Assemble and verify a `Base` `SnapV4` checkpoint from its manifest and chunks
/// (verifying `magic`, `version`, bounds, `units_merkle_root`, every `chunk_hash`
/// and `unit_hash`, and `compute_state_root() == manifest.target_state_root`),
/// without requiring a live `ValidatorSet` (for local disk reload where
/// `verify_restored_root` checks the chain anchor).
pub async fn assemble_base_state(
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<SnapStateV4, SnapV4Error> {
    if manifest.magic != SNAP_MANIFEST_MAGIC {
        return Err(SnapV4Error::InvalidMagic);
    }
    if manifest.version != SNAP_MANIFEST_VERSION {
        return Err(SnapV4Error::UnsupportedVersion(manifest.version));
    }
    if !matches!(manifest.kind, SnapshotKind::Base) {
        return Err(SnapV4Error::InvalidKind { expected: "Base" });
    }
    if manifest.units.len() > MAX_SNAP_UNITS {
        return Err(SnapV4Error::TooManyUnits {
            count: manifest.units.len(),
            max: MAX_SNAP_UNITS,
        });
    }
    if compute_units_merkle_root(&manifest.units) != manifest.units_merkle_root {
        return Err(SnapV4Error::UnitsMerkleRootMismatch);
    }
    assemble_base_state_inner(manifest, chunks).await
}

async fn assemble_base_state_inner(
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<SnapStateV4, SnapV4Error> {
    check_no_unexpected_chunks(manifest, chunks)?;
    let grouped = group_units_by_tag(manifest);

    let mut state = SnapStateV4::default();

    for (b, descs) in grouped.iter().enumerate().take(N_ACCOUNT_BUCKETS) {
        if descs.len() == 1 && descs[0].encoding == UNIT_ENC_UNCHANGED {
            if descs[0].unit_hash != empty_bucket_hash() {
                return Err(SnapV4Error::UnitHashMismatch {
                    unit_tag: b as u16,
                    sub_index: 0,
                });
            }
            continue;
        }
        state.buckets[b] = decode_bucket_full_chunks(b as u8, descs, chunks)?;
    }

    for domain in DomainUnitId::ALL {
        let descs = &grouped[domain.tag() as usize];
        match domain {
            DomainUnitId::Tokens => {
                state.tokens = decode_tokens_full_chunks(descs, chunks)?;
            }
            DomainUnitId::Contracts => {
                state.contracts = decode_contracts_full_chunks(descs, chunks)?;
            }
            other => {
                if descs.len() != 1 {
                    return Err(SnapV4Error::SubChunkCountMismatch {
                        unit_tag: other.tag(),
                        expected: 1,
                        got: descs.len() as u16,
                    });
                }
                let desc = descs[0];
                let raw = chunks.get(&(desc.unit_tag, desc.sub_index)).ok_or(
                    SnapV4Error::MissingChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    },
                )?;
                verify_unit_chunk(desc, raw)?;
                let limit = MAX_SNAP_CHUNK_BYTES as u64;
                match other {
                    DomainUnitId::Scalars => state.scalars = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::Orderbooks => {
                        state.orderbooks = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Pmm => state.pmm = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::OrderEscrow => {
                        state.order_escrow = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Staking => state.staking = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::Governance => {
                        state.governance = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Oracle => state.oracle = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::SessionKeys => {
                        state.session_keys = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Bridge => state.bridge = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::ZkMl => state.zkml_models = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::CrossShard => {
                        state.cross_shard = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::CnVrfV3 => state.cnvrf_v3 = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::PqKeys => state.pq_keys = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::EvmBindings => {
                        state.evm_bindings = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Tokens | DomainUnitId::Contracts => unreachable!(),
                }
            }
        }
    }

    let computed_root = state.compute_state_root().await?;
    if computed_root != manifest.target_state_root {
        return Err(SnapV4Error::StateRootMismatch);
    }

    Ok(state)
}

/// Verify and assemble a `Base` `SnapV4` checkpoint, including throwaway
/// `state_root == anchor.trusted_state_root` verification before returning.
pub async fn verify_and_apply_base(
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
    anchor: &TrustedSnapshotAnchor<'_>,
) -> Result<SnapStateV4, SnapV4Error> {
    verify_and_apply_base_with_key_resolver(manifest, chunks, anchor, pq_key_at_height).await
}

pub async fn verify_and_apply_base_with_key_resolver<F>(
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
    anchor: &TrustedSnapshotAnchor<'_>,
    key_resolver: F,
) -> Result<SnapStateV4, SnapV4Error>
where
    F: Fn(&ValidatorId, u64) -> Option<(PqScheme, Vec<u8>)>,
{
    validate_manifest_pre_fetch_with_key_resolver(manifest, anchor, key_resolver)?;
    if !matches!(manifest.kind, SnapshotKind::Base) {
        return Err(SnapV4Error::InvalidKind { expected: "Base" });
    }
    assemble_base_state_inner(manifest, chunks).await
}

/// Verify and apply a single `Delta` checkpoint over `base_state` without
/// requiring a live `ValidatorSet` (for local disk reload where
/// `verify_restored_root` checks the chain anchor).
pub async fn apply_delta_state(
    base_state: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
) -> Result<SnapStateV4, SnapV4Error> {
    if manifest.magic != SNAP_MANIFEST_MAGIC {
        return Err(SnapV4Error::InvalidMagic);
    }
    if manifest.version != SNAP_MANIFEST_VERSION {
        return Err(SnapV4Error::UnsupportedVersion(manifest.version));
    }
    if manifest.units.len() > MAX_SNAP_UNITS {
        return Err(SnapV4Error::TooManyUnits {
            count: manifest.units.len(),
            max: MAX_SNAP_UNITS,
        });
    }
    if compute_units_merkle_root(&manifest.units) != manifest.units_merkle_root {
        return Err(SnapV4Error::UnitsMerkleRootMismatch);
    }
    apply_delta_state_inner(
        base_state,
        base_height,
        base_state_root,
        manifest,
        chunks,
        manifest.target_state_root,
    )
    .await
}

/// Verify and apply a single `Delta` checkpoint over `base_state`, returning the
/// new verified `SnapStateV4` without mutating `base_state` on failure.
pub async fn verify_and_apply_delta(
    base_state: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
    anchor: &TrustedSnapshotAnchor<'_>,
) -> Result<SnapStateV4, SnapV4Error> {
    verify_and_apply_delta_with_key_resolver(
        base_state,
        base_height,
        base_state_root,
        manifest,
        chunks,
        anchor,
        pq_key_at_height,
    )
    .await
}

pub async fn verify_and_apply_delta_with_key_resolver<F>(
    base_state: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
    anchor: &TrustedSnapshotAnchor<'_>,
    key_resolver: F,
) -> Result<SnapStateV4, SnapV4Error>
where
    F: Fn(&ValidatorId, u64) -> Option<(PqScheme, Vec<u8>)>,
{
    validate_manifest_pre_fetch_with_key_resolver(manifest, anchor, key_resolver)?;
    apply_delta_state_inner(
        base_state,
        base_height,
        base_state_root,
        manifest,
        chunks,
        anchor.trusted_state_root,
    )
    .await
}

async fn apply_delta_state_inner(
    base_state: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    manifest: &SnapshotManifestV1,
    chunks: &BTreeMap<(u16, u16), Vec<u8>>,
    expected_target_root: [u8; 32],
) -> Result<SnapStateV4, SnapV4Error> {
    let SnapshotKind::Delta {
        base_height: declared_base_h,
        base_state_root: declared_base_root,
    } = manifest.kind
    else {
        return Err(SnapV4Error::InvalidKind { expected: "Delta" });
    };

    if declared_base_h != base_height {
        return Err(SnapV4Error::NonMonotonicDeltaChain {
            prev_height: base_height,
            next_height: declared_base_h,
        });
    }
    if declared_base_root != base_state_root {
        return Err(SnapV4Error::DeltaBaseStateRootMismatch {
            expected: base_state_root,
            actual: declared_base_root,
        });
    }

    check_no_unexpected_chunks(manifest, chunks)?;
    let grouped = group_units_by_tag(manifest);
    let mut next_state = base_state.clone();
    let limit = MAX_SNAP_CHUNK_BYTES as u64;

    // 256 account buckets
    for (b, descs) in grouped.iter().enumerate().take(N_ACCOUNT_BUCKETS) {
        let bucket = b as u8;
        let base_bucket_hash = base_state.bucket_state_hash(bucket)?;

        if descs.len() == 1 && descs[0].encoding == UNIT_ENC_UNCHANGED {
            if descs[0].unit_hash != base_bucket_hash {
                return Err(SnapV4Error::DeltaBaseUnitHashMismatch {
                    unit_tag: bucket as u16,
                });
            }
            continue;
        }
        if descs.len() == 1 && descs[0].encoding == UNIT_ENC_DELTA {
            let desc = descs[0];
            let raw =
                chunks
                    .get(&(desc.unit_tag, desc.sub_index))
                    .ok_or(SnapV4Error::MissingChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    })?;
            verify_unit_chunk(desc, raw)?;
            let delta: AccountBucketDelta = decode_canonical_exact(raw, limit)?;
            if delta.bucket != bucket {
                return Err(SnapV4Error::BucketMismatch {
                    expected: bucket,
                    got: delta.bucket,
                });
            }
            if delta.expected_base_hash != base_bucket_hash {
                return Err(SnapV4Error::DeltaBaseUnitHashMismatch {
                    unit_tag: bucket as u16,
                });
            }
            verify_strict_sorted_unique(&delta.deletes, "AccountBucketDelta.deletes")?;
            for w in delta.upserts.windows(2) {
                if w[0].address >= w[1].address {
                    return Err(SnapV4Error::UnsortedOrDuplicateAccount { bucket });
                }
            }
            for acc in &delta.upserts {
                if acc.address[0] != bucket {
                    return Err(SnapV4Error::WrongBucketAddress {
                        bucket,
                        addr_first_byte: acc.address[0],
                    });
                }
            }
            let del_set: BTreeSet<[u8; 32]> = delta.deletes.iter().copied().collect();
            for acc in &delta.upserts {
                if del_set.contains(&acc.address) {
                    return Err(SnapV4Error::UpsertDeleteOverlap {
                        domain: "AccountBucketDelta",
                    });
                }
            }

            let mut map: BTreeMap<[u8; 32], AccountState> = next_state.buckets[b]
                .drain(..)
                .map(|a| (a.address, a))
                .collect();
            for del_addr in &delta.deletes {
                if map.remove(del_addr).is_none() {
                    return Err(SnapV4Error::DeleteMissingKey {
                        domain: "AccountBucketDelta",
                    });
                }
            }
            for acc in delta.upserts {
                map.insert(acc.address, acc);
            }
            next_state.buckets[b] = map.into_values().collect();
            let result_hash = next_state.bucket_state_hash(bucket)?;
            if result_hash != desc.unit_hash {
                return Err(SnapV4Error::UnitHashMismatch {
                    unit_tag: bucket as u16,
                    sub_index: 0,
                });
            }
            continue;
        }

        // FullUnit replacement for this bucket
        for desc in descs {
            if desc.encoding != UNIT_ENC_FULL {
                return Err(SnapV4Error::InvalidEncodingForKind {
                    kind: "Delta(AccountBucket)",
                    unit_tag: bucket as u16,
                    encoding: desc.encoding,
                });
            }
        }
        next_state.buckets[b] = decode_bucket_full_chunks(bucket, descs, chunks)?;
    }

    // 16 domain units
    for domain in DomainUnitId::ALL {
        let descs = &grouped[domain.tag() as usize];
        let base_dom_hash = base_state.domain_state_hash(domain)?;

        if descs.len() == 1 && descs[0].encoding == UNIT_ENC_UNCHANGED {
            if descs[0].unit_hash != base_dom_hash {
                return Err(SnapV4Error::DeltaBaseUnitHashMismatch {
                    unit_tag: domain.tag(),
                });
            }
            continue;
        }

        if descs.len() == 1 && descs[0].encoding == UNIT_ENC_DELTA {
            let desc = descs[0];
            let raw =
                chunks
                    .get(&(desc.unit_tag, desc.sub_index))
                    .ok_or(SnapV4Error::MissingChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    })?;
            verify_unit_chunk(desc, raw)?;

            match domain {
                DomainUnitId::Scalars => {
                    let delta: ScalarsDelta = decode_canonical_exact(raw, limit)?;
                    if delta.expected_base_hash != base_dom_hash {
                        return Err(SnapV4Error::DeltaBaseUnitHashMismatch {
                            unit_tag: domain.tag(),
                        });
                    }
                    let map_diff = MapDiff {
                        expected_base_hash: delta.expected_base_hash,
                        upserts: delta.penalty_upserts,
                        deletes: delta.penalty_deletes,
                    };
                    apply_map_diff(
                        &mut next_state.scalars.penalty,
                        map_diff,
                        base_dom_hash,
                        "Scalars",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                    next_state.scalars.total_minted_nano = delta.total_minted_nano;
                }
                DomainUnitId::Tokens => {
                    let delta: TokensDelta = decode_canonical_exact(raw, limit)?;
                    apply_map_diff(
                        &mut next_state.tokens.tokens,
                        delta.diff,
                        base_dom_hash,
                        "Tokens",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                    next_state.tokens.next_nonce = delta.next_nonce;
                }
                DomainUnitId::Contracts => {
                    let delta: ContractsDelta = decode_canonical_exact(raw, limit)?;
                    apply_map_diff(
                        &mut next_state.contracts.contracts,
                        delta.diff,
                        base_dom_hash,
                        "Contracts",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                    next_state.contracts.next_nonce = delta.next_nonce;
                    next_state.contracts.last_return_data = delta.last_return_data;
                }
                DomainUnitId::Orderbooks => {
                    let diff: MapDiff<u32, OrderbookActor> = decode_canonical_exact(raw, limit)?;
                    apply_map_diff(
                        &mut next_state.orderbooks.books,
                        diff,
                        base_dom_hash,
                        "Orderbooks",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                }
                DomainUnitId::OrderEscrow => {
                    let diff: MapDiff<(u32, u64), EscrowRecord> =
                        decode_canonical_exact(raw, limit)?;
                    apply_map_diff(
                        &mut next_state.order_escrow.escrow,
                        diff,
                        base_dom_hash,
                        "OrderEscrow",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                }
                DomainUnitId::PqKeys => {
                    let diff: MapDiff<Vec<u8>, Vec<u8>> = decode_canonical_exact(raw, limit)?;
                    apply_map_diff(
                        &mut next_state.pq_keys.entries,
                        diff,
                        base_dom_hash,
                        "PqKeys",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                }
                DomainUnitId::EvmBindings => {
                    let diff: MapDiff<[u8; 20], [u8; 32]> = decode_canonical_exact(raw, limit)?;
                    apply_map_diff(
                        &mut next_state.evm_bindings.by_evm,
                        diff,
                        base_dom_hash,
                        "EvmBindings",
                    )
                    .map_err(|e| match e {
                        SnapV4Error::DeltaBaseUnitHashMismatch { .. } => {
                            SnapV4Error::DeltaBaseUnitHashMismatch {
                                unit_tag: domain.tag(),
                            }
                        }
                        other => other,
                    })?;
                }
                DomainUnitId::CrossShard => {
                    let delta: CrossShardDelta = decode_canonical_exact(raw, limit)?;
                    if delta.expected_base_hash != base_dom_hash {
                        return Err(SnapV4Error::DeltaBaseUnitHashMismatch {
                            unit_tag: domain.tag(),
                        });
                    }
                    verify_strict_sorted_unique(
                        &delta.engine_consumed_add,
                        "CrossShard.engine_consumed_add",
                    )?;
                    verify_strict_sorted_unique(
                        &delta.engine_consumed_del,
                        "CrossShard.engine_consumed_del",
                    )?;
                    verify_strict_sorted_unique(
                        &delta.runtime_consumed_add,
                        "CrossShard.runtime_consumed_add",
                    )?;
                    verify_strict_sorted_unique(
                        &delta.runtime_consumed_del,
                        "CrossShard.runtime_consumed_del",
                    )?;
                    for w in delta.produced_upserts.windows(2) {
                        if w[0].0 >= w[1].0 {
                            return Err(SnapV4Error::UnsortedOrDuplicateKey {
                                domain: "CrossShard.produced_upserts",
                            });
                        }
                    }
                    verify_strict_sorted_unique(
                        &delta.produced_deletes,
                        "CrossShard.produced_deletes",
                    )?;
                    verify_strict_sorted_unique(&delta.completed_add, "CrossShard.completed_add")?;
                    verify_strict_sorted_unique(&delta.completed_del, "CrossShard.completed_del")?;
                    for w in delta.xpc_upserts.windows(2) {
                        if w[0].tx_hash >= w[1].tx_hash {
                            return Err(SnapV4Error::UnsortedOrDuplicateKey {
                                domain: "CrossShard.xpc_upserts",
                            });
                        }
                    }
                    verify_strict_sorted_unique(&delta.xpc_deletes, "CrossShard.xpc_deletes")?;

                    for k in &delta.engine_consumed_del {
                        if !next_state.cross_shard.engine_consumed.remove(k) {
                            return Err(SnapV4Error::DeleteMissingKey {
                                domain: "CrossShard.engine_consumed",
                            });
                        }
                    }
                    for k in delta.engine_consumed_add {
                        if !next_state.cross_shard.engine_consumed.insert(k) {
                            return Err(SnapV4Error::UnsortedOrDuplicateKey {
                                domain: "CrossShard.engine_consumed_add",
                            });
                        }
                    }
                    for k in &delta.runtime_consumed_del {
                        if !next_state.cross_shard.runtime_consumed.remove(k) {
                            return Err(SnapV4Error::DeleteMissingKey {
                                domain: "CrossShard.runtime_consumed",
                            });
                        }
                    }
                    for k in delta.runtime_consumed_add {
                        if !next_state.cross_shard.runtime_consumed.insert(k) {
                            return Err(SnapV4Error::UnsortedOrDuplicateKey {
                                domain: "CrossShard.runtime_consumed_add",
                            });
                        }
                    }

                    let prod_del_set: BTreeSet<[u8; 32]> =
                        delta.produced_deletes.iter().copied().collect();
                    for (k, _, _) in &delta.produced_upserts {
                        if prod_del_set.contains(k) {
                            return Err(SnapV4Error::UpsertDeleteOverlap {
                                domain: "CrossShard.produced",
                            });
                        }
                    }
                    for k in &delta.produced_deletes {
                        if next_state.cross_shard.produced.remove(k).is_none() {
                            return Err(SnapV4Error::DeleteMissingKey {
                                domain: "CrossShard.produced",
                            });
                        }
                    }
                    for (k, tx, h) in delta.produced_upserts {
                        next_state.cross_shard.produced.insert(k, (tx, h));
                    }

                    for k in &delta.completed_del {
                        if !next_state.cross_shard.completed.remove(k) {
                            return Err(SnapV4Error::DeleteMissingKey {
                                domain: "CrossShard.completed",
                            });
                        }
                    }
                    for k in delta.completed_add {
                        if !next_state.cross_shard.completed.insert(k) {
                            return Err(SnapV4Error::UnsortedOrDuplicateKey {
                                domain: "CrossShard.completed_add",
                            });
                        }
                    }

                    let xpc_del_set: BTreeSet<[u8; 32]> =
                        delta.xpc_deletes.iter().copied().collect();
                    for rec in &delta.xpc_upserts {
                        if xpc_del_set.contains(&rec.tx_hash) {
                            return Err(SnapV4Error::UpsertDeleteOverlap {
                                domain: "CrossShard.xpc",
                            });
                        }
                    }
                    for k in &delta.xpc_deletes {
                        if next_state.cross_shard.xpc.remove(k).is_none() {
                            return Err(SnapV4Error::DeleteMissingKey {
                                domain: "CrossShard.xpc",
                            });
                        }
                    }
                    for rec in delta.xpc_upserts {
                        next_state.cross_shard.xpc.insert(rec.tx_hash, rec);
                    }
                }
                DomainUnitId::Pmm
                | DomainUnitId::Staking
                | DomainUnitId::Governance
                | DomainUnitId::Oracle
                | DomainUnitId::SessionKeys
                | DomainUnitId::Bridge
                | DomainUnitId::ZkMl
                | DomainUnitId::CnVrfV3 => {
                    return Err(SnapV4Error::InvalidEncodingForKind {
                        kind: "Delta(CompactDomain)",
                        unit_tag: domain.tag(),
                        encoding: desc.encoding,
                    });
                }
            }

            let result_hash = next_state.domain_state_hash(domain)?;
            if result_hash != desc.unit_hash {
                return Err(SnapV4Error::UnitHashMismatch {
                    unit_tag: domain.tag(),
                    sub_index: 0,
                });
            }
            continue;
        }

        // FullUnit replacement for this domain
        for desc in descs {
            if desc.encoding != UNIT_ENC_FULL {
                return Err(SnapV4Error::InvalidEncodingForKind {
                    kind: "Delta(Domain)",
                    unit_tag: domain.tag(),
                    encoding: desc.encoding,
                });
            }
        }
        match domain {
            DomainUnitId::Tokens => {
                next_state.tokens = decode_tokens_full_chunks(descs, chunks)?;
            }
            DomainUnitId::Contracts => {
                next_state.contracts = decode_contracts_full_chunks(descs, chunks)?;
            }
            other => {
                if descs.len() != 1 {
                    return Err(SnapV4Error::SubChunkCountMismatch {
                        unit_tag: other.tag(),
                        expected: 1,
                        got: descs.len() as u16,
                    });
                }
                let desc = descs[0];
                let raw = chunks.get(&(desc.unit_tag, desc.sub_index)).ok_or(
                    SnapV4Error::MissingChunk {
                        unit_tag: desc.unit_tag,
                        sub_index: desc.sub_index,
                    },
                )?;
                verify_unit_chunk(desc, raw)?;
                match other {
                    DomainUnitId::Scalars => {
                        next_state.scalars = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Orderbooks => {
                        next_state.orderbooks = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Pmm => next_state.pmm = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::OrderEscrow => {
                        next_state.order_escrow = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Staking => {
                        next_state.staking = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Governance => {
                        next_state.governance = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Oracle => next_state.oracle = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::SessionKeys => {
                        next_state.session_keys = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Bridge => next_state.bridge = decode_canonical_exact(raw, limit)?,
                    DomainUnitId::ZkMl => {
                        next_state.zkml_models = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::CrossShard => {
                        next_state.cross_shard = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::CnVrfV3 => {
                        next_state.cnvrf_v3 = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::PqKeys => {
                        next_state.pq_keys = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::EvmBindings => {
                        next_state.evm_bindings = decode_canonical_exact(raw, limit)?
                    }
                    DomainUnitId::Tokens | DomainUnitId::Contracts => unreachable!(),
                }
            }
        }
    }

    let computed_root = next_state.compute_state_root().await?;
    if computed_root != expected_target_root {
        return Err(SnapV4Error::StateRootMismatch);
    }

    Ok(next_state)
}

/// Verify and apply a bounded chain `Base -> Δ_1 -> ... -> Δ_k` (`k <= MAX_DELTA_CHAIN_LEN`).
///
/// Enforces `chain.len() <= MAX_DELTA_CHAIN_LEN` and strict height/`base_state_root`
/// monotonicity BEFORE processing any delta.
pub async fn verify_and_apply_delta_chain(
    base_state: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    chain: &[(&EncodedSnapshotV4, &TrustedSnapshotAnchor<'_>)],
) -> Result<SnapStateV4, SnapV4Error> {
    verify_and_apply_delta_chain_with_key_resolver(
        base_state,
        base_height,
        base_state_root,
        chain,
        pq_key_at_height,
    )
    .await
}

pub async fn verify_and_apply_delta_chain_with_key_resolver<F>(
    base_state: &SnapStateV4,
    base_height: u64,
    base_state_root: [u8; 32],
    chain: &[(&EncodedSnapshotV4, &TrustedSnapshotAnchor<'_>)],
    key_resolver: F,
) -> Result<SnapStateV4, SnapV4Error>
where
    F: Fn(&ValidatorId, u64) -> Option<(PqScheme, Vec<u8>)>,
{
    if chain.len() > MAX_DELTA_CHAIN_LEN {
        return Err(SnapV4Error::DeltaChainTooLong {
            len: chain.len(),
            max: MAX_DELTA_CHAIN_LEN,
        });
    }

    let mut cur_height = base_height;
    let mut cur_root = base_state_root;
    let mut cur_state = base_state.clone();

    for &(encoded, anchor) in chain {
        if anchor.target_height <= cur_height {
            return Err(SnapV4Error::NonMonotonicDeltaChain {
                prev_height: cur_height,
                next_height: anchor.target_height,
            });
        }
        cur_state = verify_and_apply_delta_with_key_resolver(
            &cur_state,
            cur_height,
            cur_root,
            &encoded.manifest,
            &encoded.chunks,
            anchor,
            &key_resolver,
        )
        .await?;
        cur_height = anchor.target_height;
        cur_root = anchor.trusted_state_root;
    }

    Ok(cur_state)
}
