//! JSON protocol shared by the CLI, the HTTP helper and the TypeScript
//! `SubprocessFalconSigner`.
//!
//! # Protocol
//!
//! Request (stdin or `POST /sign`):
//!
//! ```json
//! {
//!   "tx": {
//!     "kind": "transfer",
//!     "to": "Stl57... or 64-hex",
//!     "amount": 1000,
//!     "nonce": 7,
//!     "chain_id": 5757,
//!     "base_fee": 280000,
//!     "priority_fee_per_gas": 0,
//!     "implicit": false
//!   }
//! }
//! ```
//!
//! `contract_call`, `stake` and `unjail` use the same common fields plus:
//!
//! ```json
//! { "kind": "contract_call", "contract": "hex", "method": "sum3",
//!   "args": [{"type":"u64","value":1}], "value": 0 }
//! { "kind": "stake", "validator": "hex", "amount": 1000000 }
//! { "kind": "unjail", "validator": "hex", "top_up": null }
//! ```
//!
//! Response:
//!
//! ```json
//! { "ok": true, "tx_hex": "...", "tx_hash": "...", "from": "...",
//!   "from_stl57": "Stl57...", "nonce": 7, "chain_id": 5757,
//!   "gas_limit": 325000, "activation": true, "envelope": "pq1-explicit" }
//! ```
//!
//! Errors: `{ "ok": false, "error": { "code": "...", "message": "...",
//! "retryable": false } }`.

use serde::{Deserialize, Serialize};

use crate::address;
use crate::error::{Result, SdkError};
use crate::key::FalconKeypair;
use crate::opcode::CallArg;
use crate::tx::{SignedTx, TxBuilder, DEFAULT_CHAIN_ID, FROZEN_MIN_GAS_FLOOR};

/// Common transaction fields accepted by every kind.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TxCommon {
    #[serde(default)]
    pub nonce: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<u64>,
    #[serde(default)]
    pub priority_fee_per_gas: u64,
    #[serde(default)]
    pub source_shard: u32,
    #[serde(default)]
    pub target_shard: u32,
    /// Use an implicit PQ1 envelope (public key omitted).
    #[serde(default)]
    pub implicit: bool,
    /// Build an unbound (replayable) envelope. Testing only.
    #[serde(default)]
    pub unbound: bool,
}

/// One typed ABI argument in JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum JsonCallArg {
    I64(i64),
    U64(u64),
    I32(i32),
    Bool(bool),
    /// 64-character hex (0x optional).
    Bytes(String),
    /// Stl57 or 64-character hex.
    Address(String),
    String(String),
}

impl JsonCallArg {
    fn to_call_arg(&self) -> Result<CallArg> {
        Ok(match self {
            JsonCallArg::I64(v) => CallArg::I64(*v),
            JsonCallArg::U64(v) => CallArg::U64(*v),
            JsonCallArg::I32(v) => CallArg::I32(*v),
            JsonCallArg::Bool(v) => CallArg::Bool(*v),
            JsonCallArg::Bytes(h) => {
                let h = h.strip_prefix("0x").unwrap_or(h);
                CallArg::Bytes(
                    hex::decode(h)
                        .map_err(|e| SdkError::InvalidArgument(format!("bytes arg: {e}")))?,
                )
            }
            JsonCallArg::Address(a) => CallArg::Address(address::parse_address(a)?),
            JsonCallArg::String(s) => CallArg::String(s.clone()),
        })
    }
}

/// The transaction half of a signing request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TxIntent {
    Transfer {
        to: String,
        amount: u64,
        #[serde(flatten)]
        common: TxCommon,
    },
    ContractCall {
        contract: String,
        method: String,
        #[serde(default)]
        args: Vec<JsonCallArg>,
        #[serde(default)]
        value: u64,
        #[serde(flatten)]
        common: TxCommon,
    },
    Stake {
        validator: String,
        amount: u64,
        #[serde(flatten)]
        common: TxCommon,
    },
    Unjail {
        validator: String,
        #[serde(default)]
        top_up: Option<u64>,
        #[serde(flatten)]
        common: TxCommon,
    },
}

impl TxIntent {
    fn common(&self) -> &TxCommon {
        match self {
            TxIntent::Transfer { common, .. }
            | TxIntent::ContractCall { common, .. }
            | TxIntent::Stake { common, .. }
            | TxIntent::Unjail { common, .. } => common,
        }
    }

    fn builder(&self) -> Result<TxBuilder> {
        let b = match self {
            TxIntent::Transfer { to, amount, .. } => {
                TxBuilder::transfer(address::parse_address(to)?, *amount)
            }
            TxIntent::ContractCall {
                contract,
                method,
                args,
                value,
                ..
            } => {
                let typed: Vec<CallArg> = args
                    .iter()
                    .map(JsonCallArg::to_call_arg)
                    .collect::<Result<_>>()?;
                TxBuilder::contract_call(address::parse_address(contract)?, method, &typed, *value)?
            }
            TxIntent::Stake {
                validator, amount, ..
            } => TxBuilder::stake(address::parse_address(validator)?, *amount),
            TxIntent::Unjail {
                validator, top_up, ..
            } => TxBuilder::unjail(address::parse_address(validator)?, *top_up),
        };
        let c = self.common();
        let mut b = b
            .nonce(c.nonce)
            .chain_id(c.chain_id.unwrap_or(DEFAULT_CHAIN_ID))
            .base_fee(c.base_fee.unwrap_or(FROZEN_MIN_GAS_FLOOR))
            .priority_fee_per_gas(c.priority_fee_per_gas)
            .shards(c.source_shard, c.target_shard);
        if c.implicit {
            b = b.implicit();
        }
        if c.unbound {
            b = b.unbound();
        }
        if let Some(g) = c.gas_limit {
            b = b.gas_limit(g);
        }
        Ok(b)
    }
}

/// A signing request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub tx: TxIntent,
}

/// A successful signing response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub ok: bool,
    pub tx_hex: String,
    pub tx_hash: String,
    pub from: String,
    pub from_stl57: String,
    pub to: String,
    pub nonce: u64,
    pub chain_id: Option<u64>,
    pub gas_limit: u64,
    pub activation: bool,
    pub envelope: String,
}

/// A structured error response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignErrorResponse {
    pub ok: bool,
    pub error: SignErrorBody,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl SignErrorResponse {
    /// Render an [`SdkError`] for the wire.
    pub fn from_error(e: &SdkError) -> Self {
        let code = match e {
            SdkError::InvalidKey(_) => "invalid_key",
            SdkError::InvalidAddress(_) => "invalid_address",
            SdkError::InvalidArgument(_) => "invalid_argument",
            SdkError::SigningFailed(_) => "signing_failed",
            SdkError::VerificationFailed(_) => "verification_failed",
            SdkError::Rpc { .. } => "rpc_error",
            SdkError::Transport { .. } => "transport_error",
            SdkError::Decode(_) => "decode_error",
            SdkError::Unsupported(_) => "unsupported",
            SdkError::NonceGap { .. } => "nonce_gap",
            SdkError::FeeTooLow { .. } => "fee_too_low",
            SdkError::InsufficientBalance { .. } => "insufficient_balance",
            SdkError::NotFound(_) => "not_found",
            SdkError::RetryExhausted { .. } => "retry_exhausted",
        };
        Self {
            ok: false,
            error: SignErrorBody {
                code: code.into(),
                message: e.to_string(),
                retryable: e.is_retryable(),
            },
        }
    }
}

/// Sign one request with a loaded key.
pub fn sign_request(
    key: &FalconKeypair,
    request: &SignRequest,
) -> Result<(SignedTx, SignResponse)> {
    let builder = request.tx.builder()?;
    let signed = builder.sign(key)?;
    let env = if signed.transaction().session_grant().is_some() {
        "sf1".to_string()
    } else if signed.is_pq_activation() {
        "pq1-explicit".to_string()
    } else {
        "pq1-implicit".to_string()
    };
    let from = signed.from();
    let resp = SignResponse {
        ok: true,
        tx_hex: signed.to_hex(),
        tx_hash: signed.tx_hash_hex(),
        from: address::to_hex(&from),
        from_stl57: address::encode_stl57(&from),
        to: address::to_hex(&signed.to()),
        nonce: signed.nonce(),
        chain_id: signed.chain_id(),
        gas_limit: signed.gas_limit(),
        activation: signed.is_pq_activation(),
        envelope: env,
    };
    Ok((signed, resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_request_roundtrip() {
        let key = FalconKeypair::generate().unwrap();
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "transfer",
                "to": address::to_hex(&[7u8; 32]),
                "amount": 123,
                "nonce": 4,
                "chain_id": 5757
            }
        }))
        .unwrap();
        let (signed, resp) = sign_request(&key, &req).unwrap();
        assert_eq!(signed.nonce(), 4);
        assert!(resp.activation);
        assert_eq!(resp.envelope, "pq1-explicit");
        assert_eq!(resp.to, address::to_hex(&[7u8; 32]));
    }

    #[test]
    fn contract_call_request_roundtrip() {
        let key = FalconKeypair::generate().unwrap();
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "contract_call",
                "contract": address::to_hex(&[3u8; 32]),
                "method": "sum",
                "args": [{"type":"u64","value":7}],
                "value": 0,
                "nonce": 1
            }
        }))
        .unwrap();
        let (signed, _) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();
    }
}
