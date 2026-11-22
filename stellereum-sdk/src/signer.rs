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
use crate::envelope::EnvelopeMode;
use crate::error::{Result, SdkError};
use crate::evm::{EvmBindingBuilder, EvmCarrierBuilder};
use crate::governance::{GovAction, VoteChoice};
use crate::key::FalconKeypair;
use crate::opcode::CallArg;
use crate::protocol::ProtocolIdentity;
use crate::tx::{SignedTx, Transaction, TxBuilder, FROZEN_MIN_GAS_FLOOR};

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
    /// Fork id the caller's node reports. Defaults to this build's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_id: Option<u32>,
    /// Protocol major the caller's node reports. Defaults to this build's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_major: Option<u16>,
    /// Protocol minor the caller's node reports. Defaults to this build's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_minor: Option<u16>,
    /// Capability bits the caller's node advertises (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<u64>,
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
    /// Register an EVM address for the signing PQ key. `evm_proof` is the
    /// 65-byte secp256k1 proof of possession (`r || s || recovery_id`) over
    /// the canonical binding digest.
    EvmBinding {
        /// 20-byte EVM address, hex (0x optional).
        evm_address: String,
        /// 65-byte proof of possession, hex (0x optional).
        evm_proof: String,
        #[serde(flatten)]
        common: TxCommon,
    },
    /// Settle a value-transfer EVM intent under the signing PQ key.
    EvmCarrier {
        /// Raw EIP-155 / EIP-1559 transaction bytes, hex (0x optional).
        evm_tx: String,
        /// Recipient's bound PQ account (Stl57 or 64-hex).
        to_pq: String,
        /// Optional nonce pin; defaults to (and must equal) the EVM nonce.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        amount_nano: Option<u64>,
        #[serde(flatten)]
        common: TxCommon,
    },
    GovPropose {
        proposal_id: u64,
        title: String,
        action: serde_json::Value,
        height_observed: u64,
        #[serde(flatten)]
        common: TxCommon,
    },
    GovVote {
        proposal_id: u64,
        choice: String,
        height_observed: u64,
        #[serde(flatten)]
        common: TxCommon,
    },
    /// Sign an UNSIGNED transaction assembled by another SDK (the TypeScript
    /// package). The Rust process owns the key; the caller owns the bytes.
    /// Refused when `from` is not the signing key's address.
    Prepared {
        /// Hex of the unsigned `bincode(Transaction)` (empty signature).
        tx_hex: String,
        #[serde(flatten)]
        common: TxCommon,
    },
}

impl TxCommon {
    fn identity(&self) -> Result<ProtocolIdentity> {
        let mut identity = ProtocolIdentity::local();
        if let Some(cid) = self.chain_id {
            identity.chain_id = cid;
        }
        if let Some(fork) = self.fork_id {
            identity.fork_id = fork;
        }
        if let Some(major) = self.protocol_major {
            identity.protocol_major = major;
        }
        if let Some(minor) = self.protocol_minor {
            identity.protocol_minor = minor;
        }
        if let Some(caps) = self.capabilities {
            identity.capabilities = caps;
        }
        identity.verify()?;
        Ok(identity)
    }
}

impl TxIntent {
    fn common(&self) -> &TxCommon {
        match self {
            TxIntent::Transfer { common, .. }
            | TxIntent::ContractCall { common, .. }
            | TxIntent::Stake { common, .. }
            | TxIntent::Unjail { common, .. }
            | TxIntent::EvmBinding { common, .. }
            | TxIntent::EvmCarrier { common, .. }
            | TxIntent::GovPropose { common, .. }
            | TxIntent::GovVote { common, .. }
            | TxIntent::Prepared { common, .. } => common,
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
            TxIntent::EvmBinding { .. }
            | TxIntent::EvmCarrier { .. }
            | TxIntent::GovPropose { .. }
            | TxIntent::GovVote { .. }
            | TxIntent::Prepared { .. } => {
                return Err(SdkError::InvalidArgument(
                    "this intent kind is not built by TxBuilder".into(),
                ));
            }
        };
        let c = self.common();
        let identity = c.identity()?;
        let mut b = b
            .nonce(c.nonce)
            .identity(identity)
            .base_fee(c.base_fee.unwrap_or(FROZEN_MIN_GAS_FLOOR))
            .priority_fee_per_gas(c.priority_fee_per_gas)
            .shards(c.source_shard, c.target_shard);
        if c.unbound {
            b = b.unbound();
        } else {
            b = b.chain_id(identity.chain_id);
        }
        if c.implicit {
            b = b.implicit();
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
            SdkError::ChainIdMismatch { .. } => "chain_id_mismatch",
            SdkError::ForkIdMismatch { .. } => "fork_id_mismatch",
            SdkError::ProtocolVersionMismatch { .. } => "protocol_version_mismatch",
            SdkError::MissingEvmProof { .. } => "missing_evm_proof",
            SdkError::EvmProofMismatch { .. } => "evm_proof_mismatch",
            SdkError::InvalidEvmProof(_) => "invalid_evm_proof",
            SdkError::InvalidEvmIntent { .. } => "invalid_evm_intent",
            SdkError::CarrierNonceMismatch { .. } => "carrier_nonce_mismatch",
            SdkError::CarrierValueMismatch { .. } => "carrier_value_mismatch",
            SdkError::EvmChainIdMismatch { .. } => "evm_chain_id_mismatch",
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
    let envelope_mode = if request.tx.common().implicit {
        EnvelopeMode::Implicit
    } else {
        EnvelopeMode::Explicit
    };
    let identity = request.tx.common().identity()?;
    let signed = match &request.tx {
        TxIntent::Prepared { tx_hex, common } => {
            let bytes = decode_hex(tx_hex, "tx_hex")?;
            let tx = Transaction::decode(&bytes)?;
            let chain_id = if common.unbound {
                None
            } else {
                Some(identity.chain_id)
            };
            crate::tx::sign_unsigned(tx, key, envelope_mode, chain_id)?
        }
        TxIntent::EvmBinding {
            evm_address,
            evm_proof,
            ..
        } => {
            let evm = parse_evm_address(evm_address)?;
            let proof = decode_hex(evm_proof, "evm_proof")?;
            let mut builder = EvmBindingBuilder::new(identity, evm, proof)?;
            if let Some(g) = request.tx.common().gas_limit {
                builder = builder.gas_limit(g);
            }
            builder.nonce(request.tx.common().nonce).sign(key)?
        }
        TxIntent::EvmCarrier {
            evm_tx,
            to_pq,
            amount_nano,
            ..
        } => {
            let raw = decode_hex(evm_tx, "evm_tx")?;
            let to = address::parse_address(to_pq)?;
            let mut builder = EvmCarrierBuilder::new(identity, raw, to)?;
            if let Some(a) = amount_nano {
                builder = builder.amount_nano(*a);
            }
            if let Some(g) = request.tx.common().gas_limit {
                builder = builder.gas_limit(g);
            }
            if request.tx.common().nonce != 0 {
                builder = builder.nonce(request.tx.common().nonce);
            }
            builder.sign(key)?
        }
        TxIntent::GovPropose {
            proposal_id,
            title,
            action,
            height_observed,
            ..
        } => {
            let action = parse_gov_action(action)?;
            let builder =
                TxBuilder::gov_propose(*proposal_id, title.clone(), action, *height_observed)?;
            apply_common(builder, request.tx.common(), identity)?.sign(key)?
        }
        TxIntent::GovVote {
            proposal_id,
            choice,
            height_observed,
            ..
        } => {
            let choice = parse_vote_choice(choice)?;
            let builder = TxBuilder::gov_vote(*proposal_id, choice, *height_observed);
            apply_common(builder, request.tx.common(), identity)?.sign(key)?
        }
        _ => request.tx.builder()?.sign(key)?,
    };
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

fn apply_common(
    mut builder: TxBuilder,
    common: &TxCommon,
    identity: ProtocolIdentity,
) -> Result<TxBuilder> {
    builder = builder
        .nonce(common.nonce)
        .identity(identity)
        .base_fee(common.base_fee.unwrap_or(FROZEN_MIN_GAS_FLOOR))
        .priority_fee_per_gas(common.priority_fee_per_gas)
        .shards(common.source_shard, common.target_shard);
    if common.unbound {
        builder = builder.unbound();
    } else {
        builder = builder.chain_id(identity.chain_id);
    }
    if common.implicit {
        builder = builder.implicit();
    }
    if let Some(g) = common.gas_limit {
        builder = builder.gas_limit(g);
    }
    Ok(builder)
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>> {
    let clean = value.trim();
    let clean = clean.strip_prefix("0x").unwrap_or(clean);
    hex::decode(clean).map_err(|e| SdkError::InvalidArgument(format!("{field}: bad hex: {e}")))
}

fn parse_evm_address(value: &str) -> Result<[u8; 20]> {
    let bytes = decode_hex(value, "evm_address")?;
    if bytes.len() != 20 {
        return Err(SdkError::InvalidArgument(format!(
            "evm_address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_vote_choice(value: &str) -> Result<VoteChoice> {
    match value.to_ascii_lowercase().as_str() {
        "yes" => Ok(VoteChoice::Yes),
        "no" => Ok(VoteChoice::No),
        "abstain" => Ok(VoteChoice::Abstain),
        other => Err(SdkError::InvalidArgument(format!(
            "unknown vote choice {other:?} (yes, no, abstain)"
        ))),
    }
}

/// Parse the node's `stell_submitProposal` action JSON (`{ "type": ..., }`).
fn parse_gov_action(value: &serde_json::Value) -> Result<GovAction> {
    let object = value
        .as_object()
        .ok_or_else(|| SdkError::InvalidArgument("gov action must be a JSON object".into()))?;
    let kind = object
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SdkError::InvalidArgument("gov action needs a 'type' string".into()))?;
    let u64_arg = |name: &str| -> Result<u64> {
        object
            .get(name)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| SdkError::InvalidArgument(format!("gov action is missing '{name}'")))
    };
    let action = match kind {
        "set_min_validator_bond" => GovAction::SetMinValidatorBond(u64_arg("value")?),
        "set_equivocation_slash_bps" => GovAction::SetEquivocationSlashBps(u64_arg("value")?),
        "set_default_commission_bps" => GovAction::SetDefaultCommissionBps(u64_arg("value")?),
        "set_block_reward" => GovAction::SetBlockReward(u64_arg("value")?),
        "set_pmm_redemption_buffer_bps" => GovAction::SetPmmRedemptionBufferBps(u64_arg("value")?),
        "set_governance_quorum_bps" => GovAction::SetGovernanceQuorumBps(u64_arg("value")?),
        "signal" => GovAction::Signal(
            object
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdkError::InvalidArgument("signal needs 'text'".into()))?
                .to_string(),
        ),
        "register_oracle_publisher" | "unregister_oracle_publisher" => {
            let key = object
                .get("publisher")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdkError::InvalidArgument("oracle action needs 'publisher'".into()))
                .and_then(address::parse_address)?;
            if kind == "register_oracle_publisher" {
                GovAction::RegisterOraclePublisher(key)
            } else {
                GovAction::UnregisterOraclePublisher(key)
            }
        }
        "reset_oracle_breaker" => GovAction::ResetOracleBreaker,
        "set_min_gas_limit" => GovAction::SetMinGasLimit(u64_arg("value")?),
        "software_upgrade" | "upgrade" => {
            let name = object
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdkError::InvalidArgument("upgrade needs 'name'".into()))?
                .to_string();
            let height = u64_arg("height")?;
            let sha256 = object
                .get("sha256")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdkError::InvalidArgument("upgrade needs 'sha256'".into()))
                .and_then(|v| decode_hex(v, "sha256"))?;
            let sha256: [u8; 32] = sha256.try_into().map_err(|v: Vec<u8>| {
                SdkError::InvalidArgument(format!("sha256 must be 32 bytes, got {}", v.len()))
            })?;
            GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            }
        }
        "cancel_upgrade" => GovAction::CancelUpgrade,
        "set_fee_split_bps" => GovAction::SetFeeSplitBps {
            burn_bps: u64_arg("burn_bps")?,
            proposer_bps: u64_arg("proposer_bps")?,
            staking_bps: u64_arg("staking_bps")?,
        },
        other => {
            return Err(SdkError::InvalidArgument(format!(
                "unknown governance action type {other:?}"
            )))
        }
    };
    action.validate()?;
    Ok(action)
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

    #[test]
    fn gov_propose_set_fee_split_bps_roundtrip_and_validation() {
        let key = FalconKeypair::generate().unwrap();
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "gov_propose",
                "proposal_id": 10,
                "title": "fee split v2",
                "action": {
                    "type": "set_fee_split_bps",
                    "burn_bps": 5000,
                    "proposer_bps": 3000,
                    "staking_bps": 2000
                },
                "height_observed": 42,
                "nonce": 2
            }
        }))
        .unwrap();
        let (signed, _) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();

        let bad_req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "gov_propose",
                "proposal_id": 11,
                "title": "bad fee split",
                "action": {
                    "type": "set_fee_split_bps",
                    "burn_bps": 5000,
                    "proposer_bps": 3000,
                    "staking_bps": 1999
                },
                "height_observed": 42,
                "nonce": 3
            }
        }))
        .unwrap();
        assert!(sign_request(&key, &bad_req).is_err());

        let overflow_req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "gov_propose",
                "proposal_id": 12,
                "title": "overflow fee split",
                "action": {
                    "type": "set_fee_split_bps",
                    "burn_bps": u64::MAX,
                    "proposer_bps": 10001,
                    "staking_bps": 0
                },
                "height_observed": 42,
                "nonce": 4
            }
        }))
        .unwrap();
        assert!(sign_request(&key, &overflow_req).is_err());
    }
}
