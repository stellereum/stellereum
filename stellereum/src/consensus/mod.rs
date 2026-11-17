//! Pipelined BFT Consensus Engine (Tendermint/HotStuff-inspired)
//!
//! A real consensus protocol: proposer selection, rounds, prevote/precommit,
//! quorum certificates, value locking (safety) and view-change (liveness).
//!
//! Safety rule (Tendermint locking): a validator that precommitted value `v` at
//! round `r` is LOCKED on `v`; in later rounds it will only prevote `v` (or nil),
//! never a conflicting value. This guarantees two conflicting blocks can never
//! both reach a 2/3 precommit quorum (assuming < 1/3 Byzantine power).
//!
//! Design notes (per passport):
//!  - No global locks; the engine is a pure state machine, driven by votes.
//!  - Votes are individually Falcon-512-signed and verified on ingestion (FULL-PQ).
//!  - Equivocation (two different votes by one validator at the same height/round/
//!    kind) is recorded as evidence for slashing.
//!  - The engine is height-scoped; `ConsensusDriver` pipelines heights.

mod engine;
mod qc_split;
mod rotation;
mod sortition;
mod types;

pub use engine::*;
pub use qc_split::*;
pub use rotation::*;
pub use sortition::*;
pub use types::*;

#[cfg(test)]
#[path = "tests/core.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/round_parity_tests.rs"]
mod round_parity_tests;

#[cfg(test)]
#[path = "tests/phase_convergence_tests.rs"]
mod phase_convergence_tests;

/// Decoder fuzz regressions (Agent 1): Vote/QC bincode decode must never
/// panic on peer bytes. Appended without touching existing code.
#[cfg(test)]
#[path = "tests/decoder_fuzz_regressions.rs"]
mod decoder_fuzz_regressions;

#[cfg(test)]
#[path = "tests/post_quantum_uqc_tests.rs"]
mod post_quantum_uqc_tests;

#[cfg(test)]
#[path = "tests/qc_split_producer_tests.rs"]
mod qc_split_producer_tests;
