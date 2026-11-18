//! # Stellereum client SDK
//!
//! A thin, client-only toolkit for the live Stellereum chain:
//!
//! * **Falcon-512 keys** — generate, save/load a versioned JSON key file,
//!   derive the on-chain 32-byte address and sign.
//! * **PQ1 transaction construction** — native transfer, WASM contract call,
//!   validator stake/top-up and unjail, with the node's exact payload bytes,
//!   chain-id binding and activation surcharge.
//! * **SF1 session grants** — mint a Falcon master grant and sign delegated
//!   transactions.
//! * **JSON-RPC client** — `stell_*` reads, fee estimation, submission with
//!   retries that never re-sign, and receipt waiting.
//! * **Typed errors** — distinguish bad arguments, bad keys, node refusals,
//!   retryable transport failures and duplicate submissions.
//!
//! ## Why the node crate is not a dependency
//!
//! A wallet must not link the consensus node (tokio, axum, sled, wasmi, the
//! full RPC state). The SDK reimplements ONLY the wire pieces it mints, and
//! pins every one of them against the node crate in `tests/parity.rs`. The
//! node is a **dev-dependency** for those tests; `cargo build` never builds
//! it.
//!
//! ## Fee rule in one line
//!
//! `gas_limit >= base_fee + failure_penalty + 45_000 (explicit PQ1 only) +
//! priority_fee_per_gas` — `Mempool::required_fee_for_tx`,
//! `stellereum/src/mempool.rs:1051-1073`.

#![forbid(unsafe_code)]

pub mod address;
pub mod envelope;
pub mod error;
pub mod key;
pub mod opcode;
pub mod rpc;
pub mod session;
pub mod signer;
pub mod signer_server;
pub mod tx;
pub mod wallet;

pub use address::{encode_stl57, parse_address, to_hex};
pub use envelope::{EnvelopeMode, PqEnvelope};
pub use error::{Result, RpcErrorBody, SdkError};
pub use key::{
    derive_pq_address, verify_pq_signature, FalconKeypair, KeyFile, DEFAULT_SALT,
    FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
};
pub use opcode::{CallArg, Op, GAS_BASIC_TRANSFER};
pub use rpc::{
    Account, Block, FeeEstimate, Receipt, RetryPolicy, RpcClient, SubmitOutcome, Validator,
};
pub use session::{SessionGrant, SCOPE_ACTOR_SEND, SCOPE_ALL, SCOPE_SVM_PAYLOAD, SCOPE_TRANSFER};
pub use signer::{
    sign_request, JsonCallArg, SignErrorResponse, SignRequest, SignResponse, TxCommon, TxIntent,
};
pub use signer_server::SignerServer;
pub use tx::{
    SignedTx, Transaction, TxBuilder, CHAIN_ID_COMMITMENT_TAG, DEFAULT_CHAIN_ID,
    FROZEN_MIN_GAS_FLOOR, MASTERCHAIN_SHARD, PQ_ACTIVATION_SURCHARGE_GAS,
};
pub use wallet::Wallet;

/// Crate version (useful in CLIs and diagnostics).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Common imports.
pub mod prelude {
    pub use crate::error::{Result, SdkError};
    pub use crate::key::FalconKeypair;
    pub use crate::opcode::CallArg;
    pub use crate::rpc::{RetryPolicy, RpcClient};
    pub use crate::tx::{SignedTx, TxBuilder, DEFAULT_CHAIN_ID};
    pub use crate::wallet::Wallet;
}
