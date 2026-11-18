//! Typed errors returned by every fallible SDK operation.
//!
//! The variants are deliberately shallow: a wallet needs to distinguish
//! "fix the arguments", "fix the key", "the node refused this transaction"
//! and "the transport failed, retrying the SAME bytes is safe". RPC errors
//! keep the node's JSON-RPC code and message verbatim so callers can match
//! the node's stable refusal strings (documented in `docs/SDK.md`).

use serde::{Deserialize, Serialize};

/// Structured JSON-RPC error as served by the node.
///
/// `code` is the JSON-RPC error code (`-32602` invalid params, `-32000`
/// node rejection, ...). `data` is carried unchanged for clients that want
/// to read method-specific payloads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RpcErrorBody {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, SdkError>;

/// Everything this crate can fail with.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum SdkError {
    /// A key could not be generated, parsed or serialized.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// An address was not 32-byte hex / Stl57.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// A builder argument was out of range or inconsistent.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The Falcon signer refused or produced an unusable signature.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// A locally produced transaction did not verify; never submit it.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    /// The node answered with a JSON-RPC error object.
    #[error("rpc {method} failed ({code}): {message}")]
    Rpc {
        method: String,
        code: i64,
        message: String,
        data: Option<serde_json::Value>,
    },

    /// The HTTP transport failed before a JSON-RPC answer was received.
    ///
    /// `retryable = true` means the request MAY have reached the node; the
    /// caller must retry the exact same signed bytes (the SDK's retry helper
    /// does), never rebuild or re-sign.
    #[error("transport error during {method}: {message}")]
    Transport {
        method: String,
        message: String,
        retryable: bool,
    },

    /// The node returned JSON that did not match the documented shape.
    #[error("decode error: {0}")]
    Decode(String),

    /// The requested transaction kind/feature is not implemented by this
    /// client (for example EVM contract execution).
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The node reported a nonce gap; the caller must fill the gap.
    #[error("nonce gap: expected {expected}, got {got}")]
    NonceGap { expected: u64, got: u64 },

    /// The declared `gas_limit` is below the node's admission floor.
    #[error("fee too low: declared gas_limit {declared}, required {required}")]
    FeeTooLow { declared: u64, required: u64 },

    /// The sender cannot cover `amount + gas_limit (+ activation surcharge)`.
    #[error("insufficient balance: need {need}, have {have}")]
    InsufficientBalance { need: u64, have: u64 },

    /// The transaction was not found in the receipt index, mempool or archive.
    #[error("transaction not found: {0}")]
    NotFound(String),

    /// A retry loop exhausted its attempts. The signed bytes are unchanged
    /// and can be retried again later.
    #[error("retry exhausted after {attempts} attempts: {last}")]
    RetryExhausted { attempts: u32, last: String },
}

impl SdkError {
    /// `true` when retrying the exact same request is safe. Only transport
    /// failures and the node's explicit "already in mempool" duplicate answer
    /// qualify: a signature/argument/fee refusal will not change by retrying.
    pub fn is_retryable(&self) -> bool {
        match self {
            SdkError::Transport { retryable, .. } => *retryable,
            SdkError::RetryExhausted { .. } => true,
            SdkError::Rpc { message, .. } => is_duplicate_message(message),
            _ => false,
        }
    }

    /// `true` when the node refused because this exact transaction is already
    /// pooled. For submission this is success (the caller wanted it there).
    pub fn is_duplicate_submission(&self) -> bool {
        match self {
            SdkError::Rpc { message, .. } => is_duplicate_message(message),
            _ => false,
        }
    }
}

/// The node's stable duplicate phrasing (`MempoolError::Duplicate`, rendered
/// as `rejected: transaction already in mempool` by `stell_sendRawTransaction`).
fn is_duplicate_message(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("already in mempool")
        || m.contains("already known")
        || m.contains("duplicate transaction")
}

impl From<serde_json::Error> for SdkError {
    fn from(e: serde_json::Error) -> Self {
        SdkError::Decode(e.to_string())
    }
}
