//! Clean-room independent verifier for Stellereum L1 (Phase 1 & Phase 2).
//!
//! Provides independent, zero-node-dependency verification of:
//! - Strict v7 canonical bincode wire decoding ([`wire`])
//! - Pure-Rust NIST FIPS 206 Falcon-512 verification and PQ address derivation ([`falcon512`])
//! - Block header v4 (`STELLEREUM_HDR_V4\0`), body commitment (`STELLEREUM_BODY_V4\0`),
//!   v3 fallback (`STELLEREUM_BLOCK_V3`), `value_id`, `order_merkle_root`,
//!   cross-shard message commitments, and timestamp bounds ([`block_hash`])
//! - Clean-room consensus verification: `ValidatorSet`, `Vote`, `QuorumCertificate`
//!   (µQC + CEC + C1 split), BLAKE3/CN-VRF v3 sortition, proposer & block verification ([`consensus`])
//! - Transaction envelope verification: `PQ1`, `SF1`, `SP1` Paymaster v2, `PRIORITY`,
//!   and chain-id binding ([`tx`])
//! - Clean-room `cpat2` Merkle proofs and `CommitmentSnapshot` v5 digests ([`commitment`])
//!
//! [`verify_state_root_against_snapshot`] and [`verify_state_root_full`] close
//! the last gap between a trie `state_root` and the non-trie commitment: the
//! first proves the snapshot digest is the leaf the root commits to, the second
//! rebuilds the whole trie root from the leaf set and refuses any other root.
//!
//! # Explicit inputs only
//!
//! Every entry point takes its chain id, height, validator set, PQ keys,
//! schedule, and activation heights as explicit arguments. Nothing here reads
//! an environment variable or a global static, so a caller can verify
//! historical blocks under a frozen configuration without racing the running
//! node.
//!
//! # Example
//!
//! ```no_run
//! use stellereum_verifier::{
//!     consensus::{CommitteeSchedule, StaticPqKeyRegistry, ValidatorSet},
//!     verify_block, VerifierConfig, wire,
//! };
//!
//! # fn demo(block: wire::Block, validators: ValidatorSet, keys: StaticPqKeyRegistry)
//! #     -> Result<(), stellereum_verifier::VerifyError> {
//! let config = VerifierConfig::default();
//! verify_block(&block, None, &validators, &keys, CommitteeSchedule::ParentHash, config)
//! # }
//! ```

pub mod block_hash;
pub mod commitment;
pub mod consensus;
pub mod falcon512;
pub mod tx;
pub mod wire;

pub use commitment::{verify_state_root_against_snapshot, verify_state_root_full};

use std::fmt;

use consensus::{
    BlockVerifyContext, CommitteeSchedule, ConsensusConfig, PqKeyLookup, ValidatorSet,
};
use tx::ImplicitKeyRegistry;
use wire::{Block, QuorumCertificate, Transaction, Vote};

/// Verification configuration. All activation heights are explicit; the
/// defaults mirror the frozen protocol constants of this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifierConfig {
    /// Chain id committed by signatures and the v4 block hash.
    pub chain_id: u64,
    /// Height at which the C1 µQC/full-QC split becomes mandatory.
    pub qc_split_activation_height: u64,
    /// Height at which unbiased rejection-sampling sortition activates.
    pub sortition_unbiased_activation_height: u64,
    /// Height at which the v4 header commitment activates.
    pub header_commit_activation_height: u64,
    /// Refuse a block that carries no precommit QC (and has no `precommit_qc`).
    pub require_qc: bool,
    /// Verify every transaction in a block.
    pub verify_txs: bool,
    /// Refuse transactions that do not bind `chain_id`.
    pub require_tx_chain_id: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            chain_id: wire::DEFAULT_CHAIN_ID,
            qc_split_activation_height: consensus::QC_SPLIT_ACTIVATION_HEIGHT,
            sortition_unbiased_activation_height: consensus::SORTITION_UNBIASED_ACTIVATION_HEIGHT,
            header_commit_activation_height: block_hash::HEADER_COMMIT_ACTIVATION_HEIGHT,
            require_qc: false,
            verify_txs: false,
            require_tx_chain_id: false,
        }
    }
}

impl VerifierConfig {
    /// Project the block-level configuration into a [`ConsensusConfig`].
    pub fn consensus(&self) -> ConsensusConfig {
        ConsensusConfig {
            chain_id: self.chain_id,
            qc_split_activation_height: self.qc_split_activation_height,
            sortition_unbiased_activation_height: self.sortition_unbiased_activation_height,
            header_commit_activation_height: self.header_commit_activation_height,
        }
    }
}

/// Why a verification request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The bytes were not canonical v7 wire encoding.
    Wire(String),
    /// A block/body/order commitment did not match.
    Hash(String),
    /// A consensus rule (signature, quorum, schedule, linkage) failed.
    Consensus(String),
    /// A transaction envelope or signature was refused.
    Transaction(String),
    /// A commitment proof or digest was refused.
    Commitment(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(msg) => write!(f, "wire: {msg}"),
            Self::Hash(msg) => write!(f, "hash: {msg}"),
            Self::Consensus(msg) => write!(f, "consensus: {msg}"),
            Self::Transaction(msg) => write!(f, "transaction: {msg}"),
            Self::Commitment(msg) => write!(f, "commitment: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify one block: canonical header/body commitments, order Merkle root,
/// cross-shard message ids, proposer Falcon-512 signature, optional QC, and
/// optional transactions.
///
/// `validators` and `keys` are the set and PQ key history in force at the
/// block's height; `schedule` selects the parent-hash or CN-VRF v3 beacon
/// committee draw.
pub fn verify_block(
    block: &Block,
    qc: Option<&QuorumCertificate>,
    validators: &ValidatorSet,
    keys: &dyn PqKeyLookup,
    schedule: CommitteeSchedule,
    config: VerifierConfig,
) -> Result<(), VerifyError> {
    let mut ctx = BlockVerifyContext {
        validators,
        keys,
        schedule,
        config: config.consensus(),
        expected_prev_hash: None,
        parent_timestamp: None,
        require_qc: config.require_qc,
        verify_txs: config.verify_txs,
        require_tx_chain_id: config.require_tx_chain_id,
        implicit_registry: None,
    };
    consensus::verify_block_with_context(block, qc, &mut ctx).map_err(VerifyError::Consensus)
}

/// Verify a contiguous chain: height continuity, parent-hash linkage,
/// timestamp bounds, proposer signatures, QCs, and optional transactions.
///
/// An implicit-key registry is carried across blocks so an implicit `PQ1`
/// transaction in block N can be verified by the key first registered in an
/// earlier block.
pub fn verify_chain(
    blocks: &[Block],
    validators: &ValidatorSet,
    keys: &dyn PqKeyLookup,
    schedule: CommitteeSchedule,
    config: VerifierConfig,
) -> Result<(), VerifyError> {
    if blocks.is_empty() {
        return Err(VerifyError::Consensus("empty chain".to_string()));
    }
    let expected_shard = blocks[0].shard_id;
    let mut registry = ImplicitKeyRegistry::new();
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut prev_height: Option<u64> = None;
    let mut prev_ts: Option<u64> = None;

    for block in blocks {
        if block.shard_id != expected_shard {
            return Err(VerifyError::Consensus(format!(
                "block {} shard_id mismatch (expected {}, got {})",
                block.height, expected_shard, block.shard_id
            )));
        }
        if let Some(ph) = prev_height {
            if block.height != ph.saturating_add(1) {
                return Err(VerifyError::Consensus(format!(
                    "height discontinuity: expected {}, got {}",
                    ph.saturating_add(1),
                    block.height
                )));
            }
        }
        let mut ctx = BlockVerifyContext {
            validators,
            keys,
            schedule,
            config: config.consensus(),
            expected_prev_hash: prev_hash,
            parent_timestamp: prev_ts,
            require_qc: config.require_qc,
            verify_txs: config.verify_txs,
            require_tx_chain_id: config.require_tx_chain_id,
            implicit_registry: if config.verify_txs {
                Some(&mut registry)
            } else {
                None
            },
        };
        consensus::verify_block_with_context(block, None, &mut ctx)
            .map_err(VerifyError::Consensus)?;
        prev_hash = Some(block_hash::compute_block_hash_at(
            block,
            config.chain_id,
            config.header_commit_activation_height,
        ));
        prev_height = Some(block.height);
        prev_ts = Some(block.timestamp);
    }
    Ok(())
}

/// Verify a standalone quorum certificate: schema, µQC/CEC envelope, signer
/// attribution, schedule, and quorum power.
pub fn verify_qc(
    qc: &QuorumCertificate,
    validators: &ValidatorSet,
    keys: &dyn PqKeyLookup,
    schedule: CommitteeSchedule,
    config: VerifierConfig,
) -> Result<(), VerifyError> {
    if qc.verify_with_config(validators, keys, schedule, config.consensus()) {
        Ok(())
    } else {
        Err(VerifyError::Consensus(format!(
            "quorum certificate at height {} round {} did not verify",
            qc.height, qc.round
        )))
    }
}

/// Verify a standalone vote signature against the PQ key history.
pub fn verify_vote(
    vote: &Vote,
    keys: &dyn PqKeyLookup,
    config: VerifierConfig,
) -> Result<(), VerifyError> {
    if vote.verify(keys, config.chain_id) {
        Ok(())
    } else {
        Err(VerifyError::Consensus(format!(
            "vote by {} at height {} round {} did not verify",
            hex::encode(vote.voter),
            vote.height,
            vote.round
        )))
    }
}

/// Verify a transaction's envelope, PQ signature, stateless policies, and chain-id binding.
///
/// `registry` supplies implicit-PQ public keys (and learns explicit ones), so
/// an implicit transaction must first have its key pinned by an earlier
/// explicit transaction.
pub fn verify_tx(
    tx: &Transaction,
    expected_chain_id: u64,
    require_chain_id: bool,
    registry: &mut ImplicitKeyRegistry,
) -> Result<(), VerifyError> {
    tx::verify_tx(tx, expected_chain_id, require_chain_id, registry)
        .map_err(VerifyError::Transaction)
}

/// Verify a transaction's envelope, PQ signature, policies (including `valid_until`
/// against `now`), and chain-id binding.
pub fn verify_tx_at(
    tx: &Transaction,
    expected_chain_id: u64,
    require_chain_id: bool,
    now: u64,
    registry: &mut ImplicitKeyRegistry,
) -> Result<(), VerifyError> {
    tx::verify_tx_at(tx, expected_chain_id, require_chain_id, now, registry)
        .map_err(VerifyError::Transaction)
}

/// Verify a `cpat2` inclusion proof: `key == value` is in the trie at `root`.
pub fn verify_commitment_proof(
    root: &[u8; 32],
    key: &[u8; 32],
    value: &[u8],
    proof: &commitment::MerkleProof,
) -> Result<(), VerifyError> {
    if commitment::verify_proof(root, key, value, proof) {
        Ok(())
    } else {
        Err(VerifyError::Commitment(format!(
            "inclusion proof for {} does not fold to {}",
            hex::encode(key),
            hex::encode(root)
        )))
    }
}

/// Verify a `cpat2` exclusion proof: `key` is provably absent at `root`.
pub fn verify_commitment_exclusion(
    root: &[u8; 32],
    key: &[u8; 32],
    proof: &commitment::MerkleProof,
) -> Result<(), VerifyError> {
    if commitment::verify_exclusion_proof(root, key, proof) {
        Ok(())
    } else {
        Err(VerifyError::Commitment(format!(
            "exclusion proof for {} does not fold to {}",
            hex::encode(key),
            hex::encode(root)
        )))
    }
}
