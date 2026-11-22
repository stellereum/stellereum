//! Consensus constants folded into [`crate::protocol::FORK_ID`].
//!
//! These mirror `stellereum/src/protocol.rs:FORK_ID_RULES` and the constants it
//! references. They are duplicated (not imported) because a wallet must not
//! link the node crate; `tests/parity.rs` compares every entry against the
//! node so a consensus change fails here instead of shipping a stale wallet.
//!
//! Ruleset v2 (2026-11-19) rescaled the height-based windows for the ~240 ms
//! tempo. Ruleset v3 (2026-11-19) bound the shard id into the vote preimage
//! (domain `STELLEREUM_BFT_VOTE_V3`) and folded the proposal-slashing
//! activation sentinel. Ruleset v4 (2026-11-19) ACTIVATES proposal slashing
//! (height 0), signs the block round, and folds the deterministic
//! parent-relative block-timestamp drift bound. A change to any of these
//! values moves the fork id.

// Bound / round constants (v1).
pub const MAX_COMMIT_CERT_SIGNERS: u64 = 4_096;
pub const MAX_ROUND_AHEAD: u64 = 1_000;
pub const MAX_ROUND_ADVANCE_PER_MESSAGE: u64 = 1;
pub const MAX_SYNC_JUMPS_PER_ROUND: u64 = 8;
pub const FROZEN_ROUND_TIMEOUT_BASE_MS: u64 = 3_000;
pub const MICRO_COMMITTEE_MAX_SIZE: u64 = 128;

// Height-based consensus windows (ruleset v2).
pub const DOWNTIME_MISS_THRESHOLD: u64 = 42;
pub const DOWNTIME_PENALTY_COOLDOWN: u64 = 500;
pub const JAIL_RELEASE_DELAY_HEIGHTS: u64 = 4_000;
pub const COMMISSION_EFFECT_DELAY_HEIGHTS: u64 = 30_000;
pub const COMMISSION_CHANGE_COOLDOWN_HEIGHTS: u64 = 30_000;
pub const CNVRF_EPOCH_LEN: u64 = 30_000;
pub const CNVRF_V3_SEGMENT_LEN: u64 = 1_875;
pub const CNVRF_V3_COMMIT_LOOKAHEAD_BLOCKS: u64 = 682;
pub const PQ_ROTATION_DELAY_HEIGHTS: u64 = 30_000;
pub const MEV_KEM_ROTATION_DELAY_HEIGHTS: u64 = 30_000;
pub const MEV_EPOCH_BLOCKS: u64 = 500;
pub const MMR_EPOCH_BLOCKS: u64 = 500;
pub const DEFAULT_VDF_STEPS_PER_EPOCH: u64 = 3_000_000;

// Ruleset v3/v4: proposal-slashing activation height, folded as the 20th rule.
// `0` means ACTIVE from genesis under ruleset v4 (the block's signed round is
// what makes the same-round rule safe); any change moves the fork id.
pub const PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT: u64 = 0;

// Ruleset v4: deterministic ceiling for `block.timestamp` ahead of the parent,
// in MILLISECONDS (the node compares `MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1_000`
// seconds). Folded as the 21st rule so tightening/widening it moves the fork
// id.
pub const MAX_BLOCK_TIMESTAMP_DRIFT_MS: u64 = 60 * 60 * 1_000;

// Consensus wire/signature domains (ruleset v2, vote domain v3).
pub const SORTITION_DRAW_DOMAIN: &str = "STELL_SORTITION_V5";
pub const EQUIVOCATION_OFFENSE_DOMAIN: &[u8] = b"STELLEREUM_EQUIVOCATION_OFFENSE_V2";
pub const PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN: &[u8] =
    b"STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V2";
/// Ruleset v3 vote preimage domain: the shard id is now signed, so the tag
/// was bumped V2 -> V3 and is folded into the fork id.
pub const VOTE_SIGN_DOMAIN: &[u8] = b"STELLEREUM_BFT_VOTE_V3";
pub const VOTE_FALCON_MAGIC: &[u8; 16] = b"STELL_VOTEFAL_V1";
pub const QC_UQC_MAGIC: &[u8; 16] = b"STELL_UQC_PQ_V5_";
pub const QC_PQ_MAGIC: &[u8; 16] = b"STELL_QC_PQ_V5__";

/// Chain-wide supply partition version (ruleset v5). The cap is split across
/// the committed shard set, so this constant is a consensus rule.
pub const CHAIN_SUPPLY_PARTITION_VERSION: u64 = 1;

/// The chain-wide total supply cap in nano-STELL (9 decimals), folded into the
/// fork id because changing it redefines what a valid mint is.
pub const TOTAL_SUPPLY_CAP: u64 = 1_000_000_000 * 1_000_000_000;

// Ruleset v7: R1..R4 unified activation heights and PQ evidence retention.
pub const EXEC_HARDENING_V1_ACTIVATION_HEIGHT: u64 = 0;
pub const WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT: u64 = 0;
pub const HEADER_COMMIT_ACTIVATION_HEIGHT: u64 = 0;
pub const EVM_BINDINGS_STATE_ACTIVATION_HEIGHT: u64 = 0;
pub const PQ_LIFECYCLE_ACTIVATION_HEIGHT: u64 = 0;
pub const PQ_EVIDENCE_RETENTION_HEIGHTS: u64 = 720_000;
pub const BRIDGE_V2_ACTIVATION_HEIGHT: u64 = 0;
pub const FEE_MARKET_V2_ACTIVATION_HEIGHT: u64 = 0;
pub const SUB_NANO_STRICT_ACTIVATION_HEIGHT: u64 = 0;

// Ruleset v7 domain-separation constants.
pub const BODY_COMMITMENT_V4_DOMAIN: &[u8] = b"STELLEREUM_BODY_V4\0";
pub const HEADER_COMMIT_V4_DOMAIN: &[u8] = b"STELLEREUM_HDR_V4\0";
pub const PQ_KEY_POP_DST: &[u8] = b"STELL_PQ_KEY_POP_V1";
pub const PQ_VAL_ID_DST: &[u8] = b"STELL_VAL_ID_V1";
pub const BRIDGE_RELEASE_RECEIPT_DOMAIN_V2: &[u8] = b"STELL_BRIDGE_RELEASE_RECEIPT_V2";
pub const BRIDGE_HEADER_SIGN_DOMAIN_V2: &[u8] = b"STELL_BRIDGE_HEADER_V2";
pub const TON_MULTISIG_RELEASE_V2_DOMAIN: &[u8] = b"TON_MULTISIG_RELEASE_V2";
pub const EVM_TELEPORT_RELEASE_V2_DOMAIN: &[u8] = b"EVM_TELEPORT_RELEASE_V2";
pub const MULTISIG_RELAYER_MODEL_RELEASE_V2_DOMAIN: &[u8] =
    b"STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V2";
