//! Ethereum JSON-RPC 2.0 types and network info adapter for Stellereum.
//!
//! Provides EVM compatibility layer allowing MetaMask, Chainlist, and standard
//! Web3 tooling to communicate with the Stellereum network.
//!
//! Supported network methods:
//! - `eth_chainId`: Returns the chain ID formatted as hex quantity ("0x167d" = 5757).
//! - `net_version`: Returns the network ID formatted as decimal string ("5757").
//! - `web3_clientVersion`: Returns the client identifier ("Stellereum/v5.0.0-evm-adapter").
//! - `net_listening`: Returns true indicating client is actively listening.
//! - `net_peerCount`: Returns connected peer count formatted as hex quantity ("0x2").
//! - `eth_syncing`: Returns false when node is in sync.
//! - `eth_gasPrice`: Returns base fee in Wei as hex ("0x3eb2788000").
//! - `eth_maxPriorityFeePerGas`: Returns max priority fee per gas ("0x3b9aca00" or "0x0").
//! - `eth_feeHistory`: Returns standard EIP-1559 fee history object for block count and newest block.
//! - `eth_estimateGas`: Returns floor-aware gas estimate ("0x445c0" = 280k admission floor for transfers; pure EVM figure would be "0x5208").
//!
//! Also provides exact JSON-RPC 2.0 serialization types for:
//! - `EvmBlock`
//! - `EvmTransaction`
//! - `EvmReceipt`
//! - `EvmFeeHistory`

mod adapter;
mod binding;
mod crypto;
mod filters;
pub mod rlp;
mod tx;
mod types;

#[cfg(test)]
mod tests;

pub use adapter::*;
pub use binding::*;
pub use crypto::*;
pub use filters::*;
pub use tx::*;
pub use types::*;
