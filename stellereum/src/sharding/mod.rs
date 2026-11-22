//! Sharding, Shared-Liquidity Hub & Blockchain Consensus
//! Masterchain + Shardchain paradigm (TON architecture)
//! Dynamic & infinite sharding with auto-split and merge under load.
//! Cross-shard atomic transactions with tight-coupling cryptographic Merkle proofs.
//! Shared Sequencer for unified execution and external L2 ordering.

mod block;
mod envelope;
mod topology;
mod transaction;
mod xshard;

#[cfg(test)]
#[path = "tests/decoder_fuzz_regressions.rs"]
mod decoder_fuzz_regressions;
#[cfg(test)]
#[path = "tests/shard_header_commitment_tests.rs"]
mod shard_header_commitment_tests;
#[cfg(test)]
#[path = "tests/core.rs"]
mod tests;
#[cfg(test)]
#[path = "tests/topology_tests.rs"]
mod topology_tests;

pub use block::*;
pub use envelope::*;
pub use topology::*;
pub use transaction::*;
pub use xshard::*;
