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
//! activation sentinel. A change to any of these values moves the fork id.

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

// Ruleset v3: proposal-slashing activation sentinel, folded as the 20th rule.
// `u64::MAX` means DISABLED (see `docs/RULESET_V3.md`); activating it moves
// the fork id by construction.
pub const PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT: u64 = u64::MAX;

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
