//! Block-carried governance payloads: the exact `GovAction` / `VoteChoice`
//! bincode bytes the node serializes inside `SysCallGovPropose` /
//! `SysCallGovVote`.
//!
//! # Wire contract
//!
//! `bincode 1.3` (the node's serializer for `stellereum/src/svm.rs`):
//!
//! * enum variant = 0-based ordinal in `u32` little-endian;
//! * `String` = `u64` little-endian length followed by UTF-8 bytes;
//! * `u64` = 8 little-endian bytes;
//! * `[u8; 32]` = the 32 bytes in order (serde arrays are tuples in bincode).
//!
//! The variant order is the node's declaration order in
//! `stellereum/src/governance.rs:GovAction`, which is append-only because the
//! action is committed inside every proposal. A reorder is a hard-fork-level
//! change; the parity suite pins every variant.
//!
//! # Identity on the block path
//!
//! The proposer/voter is the TRANSACTION signer (`tx.from`), never an opcode
//! field. These builders therefore only carry the action; the SDK's
//! [`crate::tx::TxBuilder`] signs the envelope with the caller's Falcon key,
//! exactly like every other transaction.

use crate::error::{Result, SdkError};

/// Maximum proposal title (`stellereum/src/governance.rs`).
pub const MAX_PROPOSAL_TITLE_BYTES: usize = 256;
/// Maximum `Signal` text (`stellereum/src/governance.rs:MAX_SIGNAL_BYTES`).
pub const MAX_SIGNAL_BYTES: usize = 1_024;
/// Maximum software-upgrade name (`GovAction::validate`).
pub const MAX_UPGRADE_NAME_BYTES: usize = 64;
/// Minimum self-bond for `SetMinValidatorBond`
/// (`stellereum/src/staking.rs:MIN_VALIDATOR_BOND`).
pub const MIN_VALIDATOR_BOND: u64 = 1_000 * 1_000_000_000;
/// Maximum self-bond (`stellereum/src/governance.rs:MAX_VALIDATOR_BOND`).
pub const MAX_VALIDATOR_BOND: u64 = 1_000_000 * 1_000_000_000;
/// Maximum block reward (`Governance::MAX_BLOCK_REWARD_NANO`).
pub const MAX_BLOCK_REWARD_NANO: u64 = 10_000_000 * 1_000_000_000;
/// Minimum governance quorum (`GOVERNANCE_QUORUM_FLOOR_BPS`).
pub const GOVERNANCE_QUORUM_FLOOR_BPS: u64 = 3_333;
/// Frozen admission floor used as the upper bound for `SetMinGasLimit`
/// (`MAX_MIN_GAS_LIMIT = 10 * GAS_BASIC_TRANSFER`).
pub const MAX_MIN_GAS_LIMIT: u64 = 10 * crate::opcode::GAS_BASIC_TRANSFER;
/// Gas charged for `SysCallGovPropose` (`stellereum/src/svm.rs`).
pub const GAS_GOV_PROPOSE: u64 = 2_000;
/// Gas charged for `SysCallGovVote` (`stellereum/src/svm.rs`).
pub const GAS_GOV_VOTE: u64 = 600;

/// A concrete, executable parameter change.
///
/// The variant order and field order MUST match the node exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GovAction {
    SetMinValidatorBond(u64),
    SetEquivocationSlashBps(u64),
    SetDefaultCommissionBps(u64),
    SetBlockReward(u64),
    SetPmmRedemptionBufferBps(u64),
    SetGovernanceQuorumBps(u64),
    Signal(String),
    RegisterOraclePublisher([u8; 32]),
    UnregisterOraclePublisher([u8; 32]),
    ResetOracleBreaker,
    SetMinGasLimit(u64),
    SoftwareUpgrade {
        name: String,
        height: u64,
        sha256: [u8; 32],
    },
    CancelUpgrade,
    SetFeeSplitBps {
        burn_bps: u64,
        proposer_bps: u64,
        staking_bps: u64,
    },
}

impl GovAction {
    /// The node's canonical action string (`GovAction::action_type`).
    pub fn action_type(&self) -> &'static str {
        match self {
            GovAction::SetMinValidatorBond(_) => "set_min_validator_bond",
            GovAction::SetEquivocationSlashBps(_) => "set_equivocation_slash_bps",
            GovAction::SetDefaultCommissionBps(_) => "set_default_commission_bps",
            GovAction::SetBlockReward(_) => "set_block_reward",
            GovAction::SetPmmRedemptionBufferBps(_) => "set_pmm_redemption_buffer_bps",
            GovAction::SetGovernanceQuorumBps(_) => "set_governance_quorum_bps",
            GovAction::Signal(_) => "signal",
            GovAction::RegisterOraclePublisher(_) => "register_oracle_publisher",
            GovAction::UnregisterOraclePublisher(_) => "unregister_oracle_publisher",
            GovAction::ResetOracleBreaker => "reset_oracle_breaker",
            GovAction::SetMinGasLimit(_) => "set_min_gas_limit",
            GovAction::SoftwareUpgrade { .. } => "software_upgrade",
            GovAction::CancelUpgrade => "cancel_upgrade",
            GovAction::SetFeeSplitBps { .. } => "set_fee_split_bps",
        }
    }

    /// Fail-fast validation mirroring `GovAction::validate` in the node.
    ///
    /// The authoritative check is still the node's apply; this only stops a
    /// wallet from paying admission for an action that cannot pass.
    pub fn validate(&self) -> Result<()> {
        match self {
            GovAction::SetMinValidatorBond(v) => {
                if *v < MIN_VALIDATOR_BOND || *v > MAX_VALIDATOR_BOND {
                    return invalid("set_min_validator_bond out of bounds");
                }
            }
            GovAction::SetBlockReward(v) => {
                if *v > MAX_BLOCK_REWARD_NANO {
                    return invalid("set_block_reward out of bounds");
                }
            }
            GovAction::SetEquivocationSlashBps(b)
            | GovAction::SetDefaultCommissionBps(b)
            | GovAction::SetPmmRedemptionBufferBps(b) => {
                if *b > 10_000 {
                    return invalid("basis points above 10_000");
                }
            }
            GovAction::SetGovernanceQuorumBps(b) => {
                if *b < GOVERNANCE_QUORUM_FLOOR_BPS || *b > 10_000 {
                    return invalid("set_governance_quorum_bps out of bounds");
                }
            }
            GovAction::SetMinGasLimit(v) => {
                if *v == 0 || *v > MAX_MIN_GAS_LIMIT {
                    return invalid("set_min_gas_limit out of bounds");
                }
            }
            GovAction::RegisterOraclePublisher(pk) | GovAction::UnregisterOraclePublisher(pk) => {
                if *pk == [0u8; 32] {
                    return invalid("oracle publisher key must be non-zero");
                }
            }
            GovAction::Signal(text) => {
                if text.len() > MAX_SIGNAL_BYTES {
                    return invalid("signal text is too long");
                }
            }
            GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            } => {
                if name.is_empty()
                    || name.len() > MAX_UPGRADE_NAME_BYTES
                    || *height == 0
                    || *sha256 == [0u8; 32]
                {
                    return invalid("software upgrade name/height/sha256 is invalid");
                }
                if !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                {
                    return invalid("software upgrade name has unsafe characters");
                }
            }
            GovAction::CancelUpgrade => {}
            GovAction::ResetOracleBreaker => {}
            GovAction::SetFeeSplitBps {
                burn_bps,
                proposer_bps,
                staking_bps,
            } => {
                if !fee_split_bps_valid(*burn_bps, *proposer_bps, *staking_bps) {
                    return invalid("set_fee_split_bps shares must sum to 10_000");
                }
            }
        }
        Ok(())
    }

    /// Bincode bytes of this action (variant ordinal + fields).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        let tag: u32 = match self {
            GovAction::SetMinValidatorBond(v) => {
                put_u64(&mut out, *v);
                0
            }
            GovAction::SetEquivocationSlashBps(v) => {
                put_u64(&mut out, *v);
                1
            }
            GovAction::SetDefaultCommissionBps(v) => {
                put_u64(&mut out, *v);
                2
            }
            GovAction::SetBlockReward(v) => {
                put_u64(&mut out, *v);
                3
            }
            GovAction::SetPmmRedemptionBufferBps(v) => {
                put_u64(&mut out, *v);
                4
            }
            GovAction::SetGovernanceQuorumBps(v) => {
                put_u64(&mut out, *v);
                5
            }
            GovAction::Signal(text) => {
                put_string(&mut out, text);
                6
            }
            GovAction::RegisterOraclePublisher(pk) => {
                out.extend_from_slice(pk);
                7
            }
            GovAction::UnregisterOraclePublisher(pk) => {
                out.extend_from_slice(pk);
                8
            }
            GovAction::ResetOracleBreaker => 9,
            GovAction::SetMinGasLimit(v) => {
                put_u64(&mut out, *v);
                10
            }
            GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            } => {
                put_string(&mut out, name);
                put_u64(&mut out, *height);
                out.extend_from_slice(sha256);
                11
            }
            GovAction::CancelUpgrade => 12,
            GovAction::SetFeeSplitBps {
                burn_bps,
                proposer_bps,
                staking_bps,
            } => {
                put_u64(&mut out, *burn_bps);
                put_u64(&mut out, *proposer_bps);
                put_u64(&mut out, *staking_bps);
                13
            }
        };
        let mut framed = Vec::with_capacity(4 + out.len());
        framed.extend_from_slice(&tag.to_le_bytes());
        framed.extend_from_slice(&out);
        framed
    }
}

/// A vote on an open proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

impl VoteChoice {
    /// Bincode ordinal (`u32` little-endian) the node decodes.
    pub fn encode(self) -> [u8; 4] {
        let tag: u32 = match self {
            VoteChoice::Yes => 0,
            VoteChoice::No => 1,
            VoteChoice::Abstain => 2,
        };
        tag.to_le_bytes()
    }

    /// The node's `choice` string.
    pub fn as_str(self) -> &'static str {
        match self {
            VoteChoice::Yes => "yes",
            VoteChoice::No => "no",
            VoteChoice::Abstain => "abstain",
        }
    }
}

pub(crate) fn put_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn fee_split_bps_valid(burn_bps: u64, proposer_bps: u64, staking_bps: u64) -> bool {
    burn_bps
        .checked_add(proposer_bps)
        .and_then(|s| s.checked_add(staking_bps))
        == Some(10_000)
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(SdkError::InvalidArgument(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gov_action_variant_ordinals_are_append_only() {
        assert_eq!(
            GovAction::SetMinValidatorBond(1).encode()[..4],
            0u32.to_le_bytes()
        );
        assert_eq!(
            GovAction::ResetOracleBreaker.encode()[..4],
            9u32.to_le_bytes()
        );
        assert_eq!(GovAction::CancelUpgrade.encode()[..4], 12u32.to_le_bytes());
        assert_eq!(
            GovAction::SetFeeSplitBps {
                burn_bps: 5_000,
                proposer_bps: 3_000,
                staking_bps: 2_000,
            }
            .encode()[..4],
            13u32.to_le_bytes()
        );
        assert_eq!(VoteChoice::Abstain.encode(), 2u32.to_le_bytes());
    }

    #[test]
    fn software_upgrade_encodes_fields_in_order() {
        let action = GovAction::SoftwareUpgrade {
            name: "v6".into(),
            height: 77,
            sha256: [0xAB; 32],
        };
        let bytes = action.encode();
        assert_eq!(&bytes[..4], &11u32.to_le_bytes());
        assert_eq!(&bytes[4..12], &2u64.to_le_bytes());
        assert_eq!(&bytes[12..14], b"v6");
        assert_eq!(&bytes[14..22], &77u64.to_le_bytes());
        assert_eq!(&bytes[22..54], &[0xAB; 32]);
    }

    #[test]
    fn set_fee_split_bps_encodes_fields_in_order() {
        let action = GovAction::SetFeeSplitBps {
            burn_bps: 5_000,
            proposer_bps: 3_000,
            staking_bps: 2_000,
        };
        assert_eq!(action.action_type(), "set_fee_split_bps");
        let bytes = action.encode();
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..4], &13u32.to_le_bytes());
        assert_eq!(&bytes[4..12], &5_000u64.to_le_bytes());
        assert_eq!(&bytes[12..20], &3_000u64.to_le_bytes());
        assert_eq!(&bytes[20..28], &2_000u64.to_le_bytes());
    }

    #[test]
    fn action_validation_refuses_unsafe_upgrade_names() {
        let action = GovAction::SoftwareUpgrade {
            name: "../escape".into(),
            height: 1,
            sha256: [1u8; 32],
        };
        assert!(action.validate().is_err());
    }

    #[test]
    fn action_validation_enforces_fee_split_bps_sum() {
        assert!(GovAction::SetFeeSplitBps {
            burn_bps: 5_000,
            proposer_bps: 3_000,
            staking_bps: 2_000,
        }
        .validate()
        .is_ok());

        assert!(GovAction::SetFeeSplitBps {
            burn_bps: 5_000,
            proposer_bps: 3_000,
            staking_bps: 1_999,
        }
        .validate()
        .is_err());

        assert!(GovAction::SetFeeSplitBps {
            burn_bps: 5_000,
            proposer_bps: 3_000,
            staking_bps: 2_001,
        }
        .validate()
        .is_err());

        assert!(GovAction::SetFeeSplitBps {
            burn_bps: u64::MAX,
            proposer_bps: 10_001,
            staking_bps: 0,
        }
        .validate()
        .is_err());
    }
}
