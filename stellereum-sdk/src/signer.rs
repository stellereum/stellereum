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
    ContractDeploy {
        code_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        abi_json: Option<String>,
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
    ContractCallRaw {
        contract: String,
        method: String,
        #[serde(default)]
        args: Vec<i64>,
        #[serde(default)]
        calldata_hex: String,
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
            | TxIntent::ContractDeploy { common, .. }
            | TxIntent::ContractCall { common, .. }
            | TxIntent::ContractCallRaw { common, .. }
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
            TxIntent::ContractDeploy {
                code_hex, abi_json, ..
            } => {
                let code = decode_hex(code_hex, "code_hex")?;
                if code.is_empty() {
                    return Err(SdkError::InvalidArgument(
                        "contract_deploy requires non-empty code_hex".into(),
                    ));
                }
                match abi_json {
                    Some(abi) => {
                        if abi.len() > crate::opcode::MAX_CONTRACT_ABI_BYTES {
                            return Err(SdkError::InvalidArgument(format!(
                                "abi_json is {} bytes, max {}",
                                abi.len(),
                                crate::opcode::MAX_CONTRACT_ABI_BYTES
                            )));
                        }
                        TxBuilder::contract_deploy_with_abi(code, abi.as_bytes().to_vec())
                    }
                    None => TxBuilder::contract_deploy(code),
                }
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
            TxIntent::ContractCallRaw {
                contract,
                method,
                args,
                calldata_hex,
                value,
                ..
            } => {
                let h = calldata_hex.strip_prefix("0x").unwrap_or(calldata_hex);
                let calldata = hex::decode(h)
                    .map_err(|e| SdkError::InvalidArgument(format!("calldata_hex: {e}")))?;
                TxBuilder::contract_call_raw(
                    address::parse_address(contract)?,
                    method,
                    args,
                    calldata,
                    *value,
                )?
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
            let mut tx = Transaction::decode(&bytes)?;
            if common.priority_fee_per_gas != 0 {
                if tx.priority_fee_per_gas == 0 {
                    tx.priority_fee_per_gas = common.priority_fee_per_gas;
                } else if tx.priority_fee_per_gas != common.priority_fee_per_gas {
                    return Err(SdkError::InvalidArgument(format!(
                        "prepared tx priority_fee_per_gas ({}) != request priority_fee_per_gas ({})",
                        tx.priority_fee_per_gas, common.priority_fee_per_gas
                    )));
                }
            }
            let chain_id = if common.unbound {
                None
            } else {
                Some(identity.chain_id)
            };
            crate::tx::sign_unsigned_with_identity(tx, key, envelope_mode, identity, chain_id)?
        }
        TxIntent::EvmBinding {
            evm_address,
            evm_proof,
            common,
        } => {
            let evm = parse_evm_address(evm_address)?;
            let proof = decode_hex(evm_proof, "evm_proof")?;
            let tx = EvmBindingBuilder::new(identity, evm, proof)?
                .nonce(common.nonce)
                .build_unsigned(key)?;
            apply_evm_common_and_sign(tx, key, common, identity, crate::evm::EVM_BINDING_MIN_GAS)?
        }
        TxIntent::EvmCarrier {
            evm_tx,
            to_pq,
            amount_nano,
            common,
        } => {
            let raw = decode_hex(evm_tx, "evm_tx")?;
            let to = address::parse_address(to_pq)?;
            let mut builder = EvmCarrierBuilder::new(identity, raw, to)?.nonce(common.nonce);
            if let Some(a) = amount_nano {
                builder = builder.amount_nano(*a);
            }
            let tx = builder.build_unsigned(key)?;
            apply_evm_common_and_sign(tx, key, common, identity, crate::evm::EVM_CARRIER_MIN_GAS)?
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

fn apply_evm_common_and_sign(
    mut tx: Transaction,
    key: &FalconKeypair,
    common: &TxCommon,
    identity: ProtocolIdentity,
    min_gas: u64,
) -> Result<SignedTx> {
    tx.source_shard = common.source_shard;
    tx.target_shard = common.target_shard;
    tx.priority_fee_per_gas = common.priority_fee_per_gas;
    tx.gas_limit = common.gas_limit.unwrap_or_else(|| {
        let base = common.base_fee.unwrap_or(FROZEN_MIN_GAS_FLOOR);
        let surcharge = if common.implicit {
            0
        } else {
            crate::tx::PQ_ACTIVATION_SURCHARGE_GAS
        };
        min_gas
            .max(base)
            .max(FROZEN_MIN_GAS_FLOOR)
            .saturating_add(surcharge)
            .saturating_add(common.priority_fee_per_gas)
    });
    let envelope_mode = if common.implicit {
        EnvelopeMode::Implicit
    } else {
        EnvelopeMode::Explicit
    };
    let chain_id = if common.unbound {
        None
    } else {
        Some(identity.chain_id)
    };
    crate::tx::sign_unsigned_with_identity(tx, key, envelope_mode, identity, chain_id)
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

    #[test]
    fn prepared_request_preserves_priority_fee_and_custom_chain_id() {
        let key = FalconKeypair::generate().unwrap();
        let identity = ProtocolIdentity {
            chain_id: 2,
            ..ProtocolIdentity::local()
        };
        let unsigned = TxBuilder::transfer([7u8; 32], 55)
            .nonce(3)
            .identity(identity)
            .chain_id(2)
            .priority_fee_per_gas(17)
            .unsigned_transaction(key.address());
        let tx_hex = hex::encode(unsigned.encode());
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "prepared",
                "tx_hex": tx_hex,
                "chain_id": 2,
                "priority_fee_per_gas": 17
            }
        }))
        .unwrap();
        let (signed, resp) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.chain_id(), Some(2));
        assert_eq!(resp.chain_id, Some(2));
        assert_eq!(signed.priority_fee_per_gas(), 17);

        let mismatch_req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "prepared",
                "tx_hex": hex::encode(unsigned.encode()),
                "chain_id": 2,
                "priority_fee_per_gas": 99
            }
        }))
        .unwrap();
        assert!(sign_request(&key, &mismatch_req).is_err());
    }

    #[test]
    fn contract_deploy_request_roundtrip() {
        let key = FalconKeypair::generate().unwrap();
        let code = b"\0asm\x01\0\0\0".to_vec();
        let code_hex = hex::encode(&code);

        // 1. Bare contract deploy (without abi_json).
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "contract_deploy",
                "code_hex": format!("0x{code_hex}"),
                "nonce": 5
            }
        }))
        .unwrap();
        let (signed, resp) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.from(), signed.to());
        assert_eq!(signed.amount(), 0);
        assert_eq!(signed.nonce(), 5);
        assert_eq!(resp.envelope, "pq1-explicit");
        assert_eq!(
            signed.payload_bytes(),
            crate::opcode::encode_payload(&[crate::opcode::Op::DeployContract {
                code: code.clone()
            }])
        );

        // 2. Contract deploy with inline ABI JSON.
        let abi = r#"{"methods":[{"name":"get","params":[],"returns":"i64","mutates_state":false}],"events":[]}"#;
        let req_abi: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "contract_deploy",
                "code_hex": code_hex,
                "abi_json": abi,
                "nonce": 6
            }
        }))
        .unwrap();
        let (signed_abi, _) = sign_request(&key, &req_abi).unwrap();
        signed_abi.verify().unwrap();
        assert_eq!(
            signed_abi.payload_bytes(),
            crate::opcode::encode_payload(&[crate::opcode::Op::DeployContractWithAbi {
                code,
                abi_json: abi.as_bytes().to_vec(),
            }])
        );

        // 3. Empty code_hex and oversized abi_json are refused.
        let empty_req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "contract_deploy",
                "code_hex": "",
                "nonce": 7
            }
        }))
        .unwrap();
        assert!(sign_request(&key, &empty_req).is_err());

        let big_abi = "x".repeat(crate::opcode::MAX_CONTRACT_ABI_BYTES + 1);
        let big_req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "contract_deploy",
                "code_hex": "0061736d01000000",
                "abi_json": big_abi,
                "nonce": 8
            }
        }))
        .unwrap();
        assert!(sign_request(&key, &big_req).is_err());
    }

    fn test_secp_key() -> k256::ecdsa::SigningKey {
        let bytes = hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap();
        k256::ecdsa::SigningKey::from_slice(&bytes).unwrap()
    }

    fn test_evm_address(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
        use sha3::{Digest as _, Keccak256};
        let point = sk.verifying_key().to_encoded_point(false);
        let mut h = Keccak256::new();
        h.update(&point.as_bytes()[1..]);
        let hash = h.finalize();
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        out
    }

    fn test_binding_proof(pq: &[u8; 32], evm: &[u8; 20]) -> Vec<u8> {
        let sk = test_secp_key();
        let digest = crate::evm::binding_message(5757, evm, pq);
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut proof = Vec::with_capacity(65);
        proof.extend_from_slice(&sig.to_bytes()[..32]);
        proof.extend_from_slice(&sig.to_bytes()[32..]);
        proof.push(recid.to_byte());
        proof
    }

    fn rlp_encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
        if b.len() == 1 && b[0] < 0x80 {
            out.push(b[0]);
        } else if b.len() < 56 {
            out.push(0x80 + b.len() as u8);
            out.extend_from_slice(b);
        } else {
            let len_bytes = b.len().to_be_bytes();
            let first = len_bytes.iter().position(|x| *x != 0).unwrap_or(7);
            let trimmed = &len_bytes[first..];
            out.push(0xb7 + trimmed.len() as u8);
            out.extend_from_slice(trimmed);
            out.extend_from_slice(b);
        }
    }

    fn rlp_encode_u128(out: &mut Vec<u8>, v: u128) {
        let bytes = v.to_be_bytes();
        let first = bytes.iter().position(|x| *x != 0).unwrap_or(16);
        rlp_encode_bytes(out, &bytes[first..]);
    }

    fn rlp_encode_list(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if payload.len() < 56 {
            out.push(0xc0 + payload.len() as u8);
        } else {
            let len_bytes = payload.len().to_be_bytes();
            let first = len_bytes.iter().position(|x| *x != 0).unwrap_or(7);
            let trimmed = &len_bytes[first..];
            out.push(0xf7 + trimmed.len() as u8);
            out.extend_from_slice(trimmed);
        }
        out.extend_from_slice(payload);
        out
    }

    fn test_eip1559_raw(nonce: u64, value_wei: u128, to: [u8; 20]) -> Vec<u8> {
        use sha3::{Digest as _, Keccak256};
        let sk = test_secp_key();
        let mut body = Vec::new();
        rlp_encode_u128(&mut body, 5757);
        rlp_encode_u128(&mut body, nonce as u128);
        rlp_encode_u128(&mut body, 1);
        rlp_encode_u128(&mut body, 1);
        rlp_encode_u128(&mut body, 21_000);
        rlp_encode_bytes(&mut body, &to);
        rlp_encode_u128(&mut body, value_wei);
        rlp_encode_bytes(&mut body, &[]);
        body.push(0xc0); // empty accessList

        let mut preimage = vec![0x02];
        preimage.extend_from_slice(&rlp_encode_list(&body));
        let mut h = Keccak256::new();
        h.update(&preimage);
        let hash: [u8; 32] = h.finalize().into();

        let (sig, recid) = sk.sign_prehash_recoverable(&hash).unwrap();
        let sig_bytes = sig.to_bytes();
        let r_trim = sig_bytes[..32].iter().position(|x| *x != 0).unwrap_or(32);
        let s_trim = sig_bytes[32..].iter().position(|x| *x != 0).unwrap_or(32);

        rlp_encode_u128(&mut body, recid.to_byte() as u128);
        rlp_encode_bytes(&mut body, &sig_bytes[r_trim..32]);
        rlp_encode_bytes(&mut body, &sig_bytes[32 + s_trim..]);

        let mut out = vec![0x02];
        out.extend_from_slice(&rlp_encode_list(&body));
        out
    }

    #[test]
    fn contract_call_raw_request_roundtrip() {
        let key = FalconKeypair::generate().unwrap();
        let contract = [0x44u8; 32];
        let raw_cd = vec![1u8, 2, 3, 4];
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "contract_call_raw",
                "contract": address::to_hex(&contract),
                "method": "set_pq",
                "args": [42, -7],
                "calldata_hex": format!("0x{}", hex::encode(&raw_cd)),
                "value": 99,
                "nonce": 3
            }
        }))
        .unwrap();
        let (signed, resp) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.to(), contract);
        assert_eq!(signed.amount(), 99);
        assert_eq!(signed.nonce(), 3);
        assert_eq!(resp.to, address::to_hex(&contract));
        assert_eq!(
            signed.payload_bytes(),
            crate::opcode::encode_payload(&[crate::opcode::Op::call_raw(
                contract,
                "set_pq",
                &[42, -7],
                raw_cd,
            )
            .unwrap()])
        );
    }

    #[test]
    fn stake_request_roundtrip() {
        let key = FalconKeypair::generate().unwrap();
        let validator = [0x66u8; 32];
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "stake",
                "validator": address::to_hex(&validator),
                "amount": 5_000_000,
                "nonce": 2
            }
        }))
        .unwrap();
        let (signed, _) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.from(), signed.to());
        assert_eq!(signed.amount(), 5_000_000);
        assert_eq!(signed.nonce(), 2);
        assert_eq!(
            signed.payload_bytes(),
            crate::opcode::encode_payload(&[crate::opcode::Op::Stake {
                validator,
                amount: 5_000_000,
            }])
        );
    }

    #[test]
    fn unjail_request_roundtrip_with_and_without_top_up() {
        let key = FalconKeypair::generate().unwrap();
        let validator = [0x77u8; 32];

        let req_plain: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "unjail",
                "validator": address::to_hex(&validator),
                "top_up": null,
                "nonce": 4
            }
        }))
        .unwrap();
        let (signed_plain, _) = sign_request(&key, &req_plain).unwrap();
        signed_plain.verify().unwrap();
        assert_eq!(signed_plain.amount(), 0);
        assert_eq!(
            signed_plain.payload_bytes(),
            crate::opcode::encode_payload(&[crate::opcode::Op::Unjail { validator }])
        );

        let req_topup: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "unjail",
                "validator": address::to_hex(&validator),
                "top_up": 12_500,
                "nonce": 5
            }
        }))
        .unwrap();
        let (signed_topup, _) = sign_request(&key, &req_topup).unwrap();
        signed_topup.verify().unwrap();
        assert_eq!(signed_topup.amount(), 12_500);
        assert_eq!(
            signed_topup.payload_bytes(),
            crate::opcode::encode_payload(&[
                crate::opcode::Op::Stake {
                    validator,
                    amount: 12_500,
                },
                crate::opcode::Op::Unjail { validator },
            ])
        );
    }

    #[test]
    fn gov_vote_request_roundtrip_and_invalid_choice() {
        let key = FalconKeypair::generate().unwrap();
        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "gov_vote",
                "proposal_id": 14,
                "choice": "abstain",
                "height_observed": 120,
                "nonce": 1
            }
        }))
        .unwrap();
        let (signed, _) = sign_request(&key, &req).unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.from(), signed.to());
        assert_eq!(signed.amount(), 0);
        assert_eq!(
            signed.payload_bytes(),
            crate::opcode::encode_payload(&[crate::opcode::Op::GovVote {
                proposal_id: 14,
                choice: VoteChoice::Abstain,
                height_observed: 120,
            }])
        );

        let bad_req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "gov_vote",
                "proposal_id": 14,
                "choice": "maybe",
                "height_observed": 120,
                "nonce": 2
            }
        }))
        .unwrap();
        assert!(sign_request(&key, &bad_req).is_err());
    }

    #[test]
    fn evm_binding_forwards_all_common_fields() {
        let key = FalconKeypair::generate().unwrap();
        let evm = test_evm_address(&test_secp_key());
        let proof = test_binding_proof(&key.address(), &evm);

        let req: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "evm_binding",
                "evm_address": format!("0x{}", hex::encode(evm)),
                "evm_proof": format!("0x{}", hex::encode(&proof)),
                "nonce": 8,
                "base_fee": 900_000,
                "priority_fee_per_gas": 77,
                "source_shard": 1,
                "target_shard": 2,
                "implicit": true,
                "unbound": true
            }
        }))
        .unwrap();
        let (signed, resp) = sign_request(&key, &req).unwrap();
        signed.verify_with_key(&key).unwrap();
        assert_eq!(signed.nonce(), 8);
        assert!(!signed.is_pq_activation());
        assert_eq!(resp.envelope, "pq1-implicit");
        assert!(!signed.is_bound());
        assert_eq!(signed.chain_id(), None);
        assert_eq!(resp.chain_id, None);
        assert_eq!(signed.priority_fee_per_gas(), 77);
        assert_eq!(signed.gas_limit(), 900_000 + 77);
        assert_eq!(signed.transaction().source_shard, 1);
        assert_eq!(signed.transaction().target_shard, 2);
    }

    #[test]
    fn evm_carrier_forwards_common_fields_and_enforces_nonce_zero() {
        let key = FalconKeypair::generate().unwrap();
        let to_pq = [0x88u8; 32];

        // 1. Common fields are forwarded (implicit, unbound, base_fee, priority_fee, shards).
        let raw_n4 = test_eip1559_raw(4, 3_000_000_000, [0x55u8; 20]);
        let req_common: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {
                "kind": "evm_carrier",
                "evm_tx": format!("0x{}", hex::encode(&raw_n4)),
                "to_pq": address::to_hex(&to_pq),
                "nonce": 4,
                "base_fee": 950_000,
                "priority_fee_per_gas": 33,
                "source_shard": 2,
                "target_shard": 3,
                "implicit": true,
                "unbound": true
            }
        }))
        .unwrap();
        let (signed, resp) = sign_request(&key, &req_common).unwrap();
        signed.verify_with_key(&key).unwrap();
        assert_eq!(signed.nonce(), 4);
        assert_eq!(signed.amount(), 3);
        assert!(!signed.is_pq_activation());
        assert_eq!(resp.envelope, "pq1-implicit");
        assert!(!signed.is_bound());
        assert_eq!(signed.chain_id(), None);
        assert_eq!(signed.priority_fee_per_gas(), 33);
        assert_eq!(signed.gas_limit(), 950_000 + 33);
        assert_eq!(signed.transaction().source_shard, 2);
        assert_eq!(signed.transaction().target_shard, 3);

        // 2. Explicit nonce == 0 succeeds when the EVM intent has nonce == 0.
        let raw_n0 = test_eip1559_raw(0, 2_000_000_000, [0x55u8; 20]);
        let req_n0 = SignRequest {
            tx: TxIntent::EvmCarrier {
                evm_tx: hex::encode(&raw_n0),
                to_pq: address::to_hex(&to_pq),
                amount_nano: Some(2),
                common: TxCommon {
                    nonce: 0,
                    ..TxCommon::default()
                },
            },
        };
        let (signed_n0, _) = sign_request(&key, &req_n0).unwrap();
        signed_n0.verify().unwrap();
        assert_eq!(signed_n0.nonce(), 0);
        assert_eq!(signed_n0.amount(), 2);

        // 3. Explicit nonce == 0 is NOT ignored when the EVM intent has nonce == 4.
        let req_mismatch = SignRequest {
            tx: TxIntent::EvmCarrier {
                evm_tx: hex::encode(&raw_n4),
                to_pq: address::to_hex(&to_pq),
                amount_nano: None,
                common: TxCommon {
                    nonce: 0,
                    ..TxCommon::default()
                },
            },
        };
        let err = sign_request(&key, &req_mismatch).unwrap_err();
        assert_eq!(err, SdkError::CarrierNonceMismatch { evm: 4, tx: 0 });
    }
}
