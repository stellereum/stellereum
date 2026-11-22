//! Protocol version, fork identity and capability mirror of the node.
//!
//! # Why the SDK mirrors these constants
//!
//! A transaction that is valid under one consensus ruleset can be invalid (or
//! worse, ambiguous) under another. The node exposes its identity in
//! `stellereum/src/protocol.rs` (`PROTOCOL_MAJOR`, `PROTOCOL_MINOR`,
//! `FORK_ID`, `CHAIN_IDENTITY`, `startup_line()`, `version_info()`) and refuses
//! consensus participation to a peer with a different fork id. The SDK must do
//! the same BEFORE it signs: a wallet that builds for a stale fork produces
//! bytes the node will reject, and the user pays the round trip.
//!
//! The mirror is pinned by `tests/parity.rs` against the node crate, so a
//! consensus-rules change that moves `FORK_ID` fails the parity suite here
//! instead of silently shipping a stale wallet.
//!
//! # What a caller configures
//!
//! [`ProtocolIdentity`] is the identity of the node a wallet talks to. Build
//! it from [`ProtocolIdentity::local`] for the chain this crate was compiled
//! for, or from the node's own JSON (`ProtocolIdentity::from_json`) once the
//! RPC exposes it. Every builder calls [`ProtocolIdentity::verify`] and
//! [`ProtocolIdentity::verify_chain_id`] before signing.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SdkError};
use crate::tx::DEFAULT_CHAIN_ID;

/// Semver-ish MAJOR of the consensus/control protocol
/// (`stellereum/src/protocol.rs:PROTOCOL_MAJOR`).
pub const PROTOCOL_MAJOR: u16 = 1;

/// Semver-ish MINOR of the consensus/control protocol
/// (`stellereum/src/protocol.rs:PROTOCOL_MINOR`).
pub const PROTOCOL_MINOR: u16 = 0;

/// Version of the consensus rule logic not captured by a hashed constant
/// (`stellereum/src/protocol.rs:CONSENSUS_RULESET_VERSION`).
pub const CONSENSUS_RULESET_VERSION: u32 = 7;

/// Version of the folded domain-separation string set
/// (`stellereum/src/protocol.rs:DOMAIN_SET_VERSION`).
pub const DOMAIN_SET_VERSION: u32 = 4;

/// The consensus rule constants folded into [`FORK_ID`], in the node's order
/// (`stellereum/src/protocol.rs:FORK_ID_RULES`).
///
/// Mirrored so [`derive_fork_id`] can be checked against the node in the
/// parity suite and so a consensus-rule edit is visible here, not just as a
/// changed literal.
pub const FORK_ID_RULES: &[u64] = &[
    crate::constants::MAX_COMMIT_CERT_SIGNERS,
    crate::constants::MAX_ROUND_AHEAD,
    crate::constants::MAX_ROUND_ADVANCE_PER_MESSAGE,
    crate::constants::MAX_SYNC_JUMPS_PER_ROUND,
    crate::constants::FROZEN_ROUND_TIMEOUT_BASE_MS,
    crate::constants::MICRO_COMMITTEE_MAX_SIZE,
    crate::constants::DOWNTIME_MISS_THRESHOLD,
    crate::constants::DOWNTIME_PENALTY_COOLDOWN,
    crate::constants::JAIL_RELEASE_DELAY_HEIGHTS,
    crate::constants::COMMISSION_EFFECT_DELAY_HEIGHTS,
    crate::constants::COMMISSION_CHANGE_COOLDOWN_HEIGHTS,
    crate::constants::CNVRF_EPOCH_LEN,
    crate::constants::CNVRF_V3_SEGMENT_LEN,
    crate::constants::CNVRF_V3_COMMIT_LOOKAHEAD_BLOCKS,
    crate::constants::PQ_ROTATION_DELAY_HEIGHTS,
    crate::constants::MEV_KEM_ROTATION_DELAY_HEIGHTS,
    crate::constants::MEV_EPOCH_BLOCKS,
    crate::constants::MMR_EPOCH_BLOCKS,
    crate::constants::DEFAULT_VDF_STEPS_PER_EPOCH,
    crate::constants::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT,
    crate::constants::MAX_BLOCK_TIMESTAMP_DRIFT_MS,
    crate::constants::CHAIN_SUPPLY_PARTITION_VERSION,
    crate::constants::TOTAL_SUPPLY_CAP,
    crate::constants::EXEC_HARDENING_V1_ACTIVATION_HEIGHT,
    crate::constants::WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT,
    crate::constants::HEADER_COMMIT_ACTIVATION_HEIGHT,
    crate::constants::EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
    crate::constants::PQ_LIFECYCLE_ACTIVATION_HEIGHT,
    crate::constants::PQ_EVIDENCE_RETENTION_HEIGHTS,
    crate::constants::BRIDGE_V2_ACTIVATION_HEIGHT,
    crate::constants::FEE_MARKET_V2_ACTIVATION_HEIGHT,
    crate::constants::SUB_NANO_STRICT_ACTIVATION_HEIGHT,
];

const FNV_OFFSET: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

const fn fnv1a32(seed: u32, bytes: &[u8]) -> u32 {
    let mut h = seed;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u32;
        h = h.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    h
}

const fn fold_u64(h: u32, v: u64) -> u32 {
    fnv1a32(h, &v.to_le_bytes())
}

/// Pure derivation of the node's fork id (`stellereum/src/protocol.rs`).
///
/// Exposed so a caller can compute a candidate id and so the parity suite can
/// prove the SDK mirrors the node instead of carrying a magic literal.
pub const fn derive_fork_id(chain_id: u64, ruleset_version: u32, rules: &[u64]) -> u32 {
    let mut h = fnv1a32(FNV_OFFSET, b"STELL_FORK_ID_V1");
    h = fnv1a32(h, &DOMAIN_SET_VERSION.to_le_bytes());
    h = fold_u64(h, chain_id);
    h = fnv1a32(h, &ruleset_version.to_le_bytes());
    h = fnv1a32(h, crate::constants::SORTITION_DRAW_DOMAIN.as_bytes());
    h = fnv1a32(h, crate::constants::EQUIVOCATION_OFFENSE_DOMAIN);
    h = fnv1a32(h, crate::constants::PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN);
    h = fnv1a32(h, crate::constants::VOTE_SIGN_DOMAIN);
    h = fnv1a32(h, crate::constants::VOTE_FALCON_MAGIC);
    h = fnv1a32(h, crate::constants::QC_UQC_MAGIC);
    h = fnv1a32(h, crate::constants::QC_PQ_MAGIC);
    h = fnv1a32(h, crate::constants::BODY_COMMITMENT_V4_DOMAIN);
    h = fnv1a32(h, crate::constants::HEADER_COMMIT_V4_DOMAIN);
    h = fnv1a32(h, crate::constants::PQ_KEY_POP_DST);
    h = fnv1a32(h, crate::constants::PQ_VAL_ID_DST);
    h = fnv1a32(h, crate::constants::BRIDGE_RELEASE_RECEIPT_DOMAIN_V2);
    h = fnv1a32(h, crate::constants::BRIDGE_HEADER_SIGN_DOMAIN_V2);
    h = fnv1a32(h, crate::constants::TON_MULTISIG_RELEASE_V2_DOMAIN);
    h = fnv1a32(h, crate::constants::EVM_TELEPORT_RELEASE_V2_DOMAIN);
    h = fnv1a32(
        h,
        crate::constants::MULTISIG_RELAYER_MODEL_RELEASE_V2_DOMAIN,
    );
    let mut i = 0;
    while i < rules.len() {
        h = fold_u64(h, rules[i]);
        i += 1;
    }
    h
}

/// The consensus ruleset identifier this SDK build speaks
/// (`stellereum/src/protocol.rs:FORK_ID`, ruleset v7).
pub const FORK_ID: u32 = derive_fork_id(DEFAULT_CHAIN_ID, CONSENSUS_RULESET_VERSION, FORK_ID_RULES);

/// Capability bit of `COMPACT_GOSSIP` (`infnode::proto::Capabilities`).
pub const CAP_COMPACT_GOSSIP: u64 = 1 << 0;
/// Capability bit of `MESH_DIRECT`.
pub const CAP_MESH_DIRECT: u64 = 1 << 1;
/// Every capability this build implements (`Capabilities::ALL`).
pub const CAPABILITIES: u64 = CAP_COMPACT_GOSSIP | CAP_MESH_DIRECT;

/// The complete identity of the node a builder targets.
///
/// `chain_id` is the node's configured chain id (`stell_chainId`), the
/// protocol pair is the control protocol, and `fork_id` identifies the
/// consensus ruleset. A wallet built for a different fork must NOT sign for
/// this node: the bytes would be refused at admission and any local
/// verification would disagree with consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolIdentity {
    /// The node's configured chain id (`stell_chainId`).
    pub chain_id: u64,
    /// Control-protocol major.
    pub protocol_major: u16,
    /// Control-protocol minor.
    pub protocol_minor: u16,
    /// Consensus ruleset identifier.
    pub fork_id: u32,
    /// Advertised capability bits.
    #[serde(default)]
    pub capabilities: u64,
}

impl ProtocolIdentity {
    /// The identity of the chain this crate was compiled for.
    pub const fn local() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            fork_id: FORK_ID,
            capabilities: CAPABILITIES,
        }
    }

    /// Parse the node's `version_info()` shape (the machine-readable identity
    /// an RPC exposes). Missing optional fields default to the local values,
    /// but `chain_id`, `fork_id` and the protocol pair are required.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let chain_id = value
            .get("chain_id")
            .or_else(|| value.get("chainId"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| SdkError::Decode("protocol identity: missing chain_id".into()))?;
        let protocol_major = value
            .get("protocol_major")
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| SdkError::Decode("protocol identity: missing protocol_major".into()))?;
        let protocol_minor = value
            .get("protocol_minor")
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| SdkError::Decode("protocol identity: missing protocol_minor".into()))?;
        let fork_id = value
            .get("fork_id")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| SdkError::Decode("protocol identity: missing fork_id".into()))?;
        let capabilities = value
            .get("capabilities")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(Self {
            chain_id,
            protocol_major,
            protocol_minor,
            fork_id,
            capabilities,
        })
    }

    /// The protocol version as `major.minor`.
    pub fn protocol_version(&self) -> String {
        format!("{}.{}", self.protocol_major, self.protocol_minor)
    }

    /// `0x`-prefixed fork id, for logs and diagnostics.
    pub fn fork_id_hex(&self) -> String {
        format!("0x{:08x}", self.fork_id)
    }

    /// The one-line form mirroring the node's `protocol::startup_line()`.
    pub fn startup_line(&self) -> String {
        format!(
            "[protocol] version {} fork_id {} capabilities 0x{:016x} ruleset_version {}",
            self.protocol_version(),
            self.fork_id_hex(),
            self.capabilities,
            CONSENSUS_RULESET_VERSION,
        )
    }

    /// Refuse an identity that does not speak this SDK build's protocol/fork.
    ///
    /// This is the guard every builder runs. Both halves are errors on
    /// purpose: a fork mismatch means the consensus RULES differ, and a
    /// protocol version mismatch means the control wire differs.
    pub fn verify(&self) -> Result<()> {
        if self.protocol_major != PROTOCOL_MAJOR || self.protocol_minor != PROTOCOL_MINOR {
            return Err(SdkError::ProtocolVersionMismatch {
                expected: format!("{PROTOCOL_MAJOR}.{PROTOCOL_MINOR}"),
                got: self.protocol_version(),
            });
        }
        if self.fork_id != FORK_ID {
            return Err(SdkError::ForkIdMismatch {
                expected: FORK_ID,
                got: self.fork_id,
            });
        }
        Ok(())
    }

    /// Refuse a chain id that is not this identity's chain id.
    pub fn verify_chain_id(&self, chain_id: u64) -> Result<()> {
        if chain_id != self.chain_id {
            return Err(SdkError::ChainIdMismatch {
                expected: self.chain_id,
                got: chain_id,
            });
        }
        Ok(())
    }

    /// Verify the identity AND a transaction chain id in one call.
    pub fn verify_for_chain(&self, chain_id: u64) -> Result<()> {
        self.verify()?;
        self.verify_chain_id(chain_id)
    }
}

/// The machine-readable identity this SDK build speaks, in the shape of the
/// node's `protocol::version_info()`.
pub fn local_version_info() -> serde_json::Value {
    serde_json::json!({
        "protocol_version": format!("{PROTOCOL_MAJOR}.{PROTOCOL_MINOR}"),
        "protocol_major": PROTOCOL_MAJOR,
        "protocol_minor": PROTOCOL_MINOR,
        "fork_id": FORK_ID,
        "fork_id_hex": format!("0x{FORK_ID:08x}"),
        "capabilities": CAPABILITIES,
        "capabilities_names": capability_names(CAPABILITIES),
        "consensus_ruleset_version": CONSENSUS_RULESET_VERSION,
        "domain_set_version": DOMAIN_SET_VERSION,
        "chain_id": DEFAULT_CHAIN_ID,
    })
}

/// Names of the known capability bits, in a stable order.
pub fn capability_names(caps: u64) -> Vec<&'static str> {
    let mut out = Vec::new();
    if caps & CAP_COMPACT_GOSSIP != 0 {
        out.push("COMPACT_GOSSIP");
    }
    if caps & CAP_MESH_DIRECT != 0 {
        out.push("MESH_DIRECT");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_identity_verifies() {
        let id = ProtocolIdentity::local();
        id.verify().unwrap();
        id.verify_for_chain(DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(id.fork_id_hex(), "0x3ae00ebc");
        assert!(id.startup_line().contains("fork_id 0x3ae00ebc"));
    }

    #[test]
    fn foreign_chain_is_refused_by_name() {
        let id = ProtocolIdentity::local();
        let err = id.verify_for_chain(1).unwrap_err();
        assert!(matches!(
            err,
            SdkError::ChainIdMismatch {
                expected: 5757,
                got: 1
            }
        ));
    }

    #[test]
    fn foreign_fork_is_refused_by_name() {
        let mut id = ProtocolIdentity::local();
        id.fork_id ^= 1;
        assert!(matches!(id.verify(), Err(SdkError::ForkIdMismatch { .. })));
    }

    #[test]
    fn foreign_protocol_version_is_refused_by_name() {
        let mut id = ProtocolIdentity::local();
        id.protocol_minor += 1;
        assert!(matches!(
            id.verify(),
            Err(SdkError::ProtocolVersionMismatch { .. })
        ));
    }

    #[test]
    fn version_info_roundtrips() {
        let id = ProtocolIdentity::local();
        let mut json = local_version_info();
        json["chain_id"] = serde_json::json!(DEFAULT_CHAIN_ID);
        assert_eq!(ProtocolIdentity::from_json(&json).unwrap(), id);
    }
}
