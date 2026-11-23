//! The handful of SVM opcodes the SDK can mint, encoded with the node's
//! bincode layout.
//!
//! `bincode 1.3` (the node's serializer, `stellereum/src/svm.rs:467`) writes:
//!
//! * a `Vec<T>` as `u64` little-endian length followed by the elements;
//! * an enum variant as its 0-based ordinal in `u32` little-endian;
//! * `u64`/`i64` as 8 little-endian bytes, arrays as their bytes in order.
//!
//! The discriminants used here are pinned by `tests/parity.rs`, which
//! serializes the node's real `OpCode` values with `bincode` and compares
//! byte-for-byte. Only these operations are needed by the wallet shapes in
//! scope; everything else is deliberately absent from this client.

use crate::error::{Result, SdkError};
use crate::evm::put_vec;
use crate::governance::{put_string, put_u64, GovAction, VoteChoice};

/// Bincode discriminant of `OpCode::SysCallStake`
/// (`stellereum/src/svm.rs:548`, 22nd variant).
pub const OP_STAKE: u32 = 21;
/// Bincode discriminant of `OpCode::SysCallCallContractArgs`
/// (`stellereum/src/svm.rs:994`).
pub const OP_CALL_CONTRACT_ARGS: u32 = 50;
/// Bincode discriminant of `OpCode::SysCallGovPropose`.
pub const OP_GOV_PROPOSE: u32 = 53;
/// Bincode discriminant of `OpCode::SysCallGovVote`.
pub const OP_GOV_VOTE: u32 = 54;
/// Bincode discriminant of `OpCode::SysCallUnjail`
/// (`stellereum/src/svm.rs:1124`).
pub const OP_UNJAIL: u32 = 56;
/// Bincode discriminant of `OpCode::SysCallEvmCarrier`.
pub const OP_EVM_CARRIER: u32 = 57;
/// Bincode discriminant of `OpCode::SysCallBindEvmAddress`.
pub const OP_BIND_EVM_ADDRESS: u32 = 58;

/// `GAS_BASIC_TRANSFER` (`stellereum/src/svm.rs:36`).
pub const GAS_BASIC_TRANSFER: u64 = 280_000;
/// `GAS_STAKE_BOND` (`stellereum/src/svm.rs:92`).
pub const GAS_STAKE_BOND: u64 = 2_000;
/// `GAS_GOV_PROPOSE` (`stellereum/src/svm.rs`).
pub const GAS_GOV_PROPOSE: u64 = 2_000;
/// `GAS_GOV_VOTE` (`stellereum/src/svm.rs`).
pub const GAS_GOV_VOTE: u64 = 600;
/// Base gas for the EVM carrier/binding opcodes (`svm.rs`).
pub const GAS_EVM_CARRIER_BASE: u64 = 2_000;
/// Base gas of one Falcon verify (`svm.rs:GAS_PQ_VERIFY_BASE`).
pub const GAS_PQ_VERIFY_BASE: u64 = 1_500;
/// Per-byte gas of one Falcon verify (`svm.rs:GAS_PQ_VERIFY_PER_BYTE`).
pub const GAS_PQ_VERIFY_PER_BYTE: u64 = 2;
/// `GAS_STAKE_UNBOND` (`stellereum/src/svm.rs:94`).
pub const GAS_STAKE_UNBOND: u64 = 800;
/// `GAS_CONTRACT_CALL` (`stellereum/src/svm.rs:63`).
pub const GAS_CONTRACT_CALL: u64 = 1_000;
/// `GAS_CONTRACT_CALL_PER_ARG` (`stellereum/src/svm.rs:65`).
pub const GAS_CONTRACT_CALL_PER_ARG: u64 = 10;
/// `GAS_CONTRACT_CALL_PER_BYTE` (`stellereum/src/svm.rs:70`).
pub const GAS_CONTRACT_CALL_PER_BYTE: u64 = 2;

/// Maximum ABI arguments for one call.
///
/// Mirrors `stellereum/src/contract_abi.rs:MAX_ABI_ARGS` AND the VM's
/// `stellereum/src/contract.rs:MAX_CONTRACT_CALL_ARGS`; both are 8. A wider
/// call is refused by the VM at execution, so allowing more here would only
/// let a wallet sign and pay for a transaction that is guaranteed to revert.
pub const MAX_ABI_ARGS: usize = 8;
/// Maximum ABI blob length (`stellereum/src/contract_abi.rs:64`).
pub const MAX_ABI_BLOB_LEN: usize = 1024 * 1024;

/// A typed contract-call argument. The binary encoding mirrors
/// `AbiValue::encode_payload` in `stellereum/src/contract_abi.rs:504`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallArg {
    I64(i64),
    U64(u64),
    I32(i32),
    Bool(bool),
    Bytes(Vec<u8>),
    Address([u8; 32]),
    String(String),
}

impl CallArg {
    /// Stable ABI type tag (`stellereum/src/contract_abi.rs:67-79`).
    pub fn tag(&self) -> u8 {
        match self {
            CallArg::I64(_) => 0x01,
            CallArg::U64(_) => 0x02,
            CallArg::I32(_) => 0x03,
            CallArg::Bool(_) => 0x04,
            CallArg::Bytes(_) => 0x05,
            CallArg::Address(_) => 0x06,
            CallArg::String(_) => 0x07,
        }
    }

    /// Scalar projection used in `SysCallCallContractArgs.args`, exactly the
    /// `AbiValue::as_i64().unwrap_or(0)` mapping `src/rpc/reads.rs` applies.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            CallArg::I64(v) => Some(*v),
            CallArg::U64(v) => Some(*v as i64),
            CallArg::I32(v) => Some(*v as i64),
            CallArg::Bool(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    fn encode_payload(&self) -> Result<Vec<u8>> {
        Ok(match self {
            CallArg::I64(v) => v.to_be_bytes().to_vec(),
            CallArg::U64(v) => v.to_be_bytes().to_vec(),
            CallArg::I32(v) => v.to_be_bytes().to_vec(),
            CallArg::Bool(v) => vec![u8::from(*v)],
            CallArg::Bytes(b) => {
                if b.len() > MAX_ABI_BLOB_LEN {
                    return Err(SdkError::InvalidArgument(format!(
                        "ABI blob is {} bytes, max {MAX_ABI_BLOB_LEN}",
                        b.len()
                    )));
                }
                let mut out = Vec::with_capacity(4 + b.len());
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
                out
            }
            CallArg::Address(a) => a.to_vec(),
            CallArg::String(s) => {
                let b = s.as_bytes();
                if b.len() > MAX_ABI_BLOB_LEN {
                    return Err(SdkError::InvalidArgument(format!(
                        "ABI string is {} bytes, max {MAX_ABI_BLOB_LEN}",
                        b.len()
                    )));
                }
                let mut out = Vec::with_capacity(4 + b.len());
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
                out
            }
        })
    }
}

/// Encode the `calldata` half of `SysCallCallContractArgs`.
///
/// Exactly `u32 LE count || (tag || payload)*`, matching
/// `ContractAbi::encode_args` (`stellereum/src/contract_abi.rs:999`).
pub fn encode_calldata(args: &[CallArg]) -> Result<Vec<u8>> {
    if args.len() > MAX_ABI_ARGS {
        return Err(SdkError::InvalidArgument(format!(
            "{} arguments, max {MAX_ABI_ARGS}",
            args.len()
        )));
    }
    let mut out = Vec::with_capacity(4 + args.len() * 9);
    out.extend_from_slice(&(args.len() as u32).to_le_bytes());
    for a in args {
        out.push(a.tag());
        out.extend_from_slice(&a.encode_payload()?);
    }
    Ok(out)
}

/// One supported opcode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// `SysCallStake { validator, amount }`.
    Stake { validator: [u8; 32], amount: u64 },
    /// `SysCallUnjail { validator }`.
    Unjail { validator: [u8; 32] },
    /// `SysCallCallContractArgs { contract, method, args, calldata }`.
    CallContractArgs {
        contract: [u8; 32],
        method: Vec<u8>,
        args: Vec<i64>,
        calldata: Vec<u8>,
    },
    /// `SysCallGovPropose { proposal_id, title, action, height_observed }`.
    GovPropose {
        proposal_id: u64,
        title: String,
        action: GovAction,
        height_observed: u64,
    },
    /// `SysCallGovVote { proposal_id, choice, height_observed }`.
    GovVote {
        proposal_id: u64,
        choice: VoteChoice,
        height_observed: u64,
    },
    /// `SysCallEvmCarrier(EvmCarrierIntent)`.
    EvmCarrier {
        chain_id: u64,
        evm_tx: Vec<u8>,
        evm_address: [u8; 20],
        pq_pubkey: Vec<u8>,
        evm_signature: Vec<u8>,
    },
    /// `SysCallBindEvmAddress(EvmAddressClaim)`.
    BindEvmAddress {
        chain_id: u64,
        evm_address: [u8; 20],
        pq_pubkey: Vec<u8>,
        binding_signature: Vec<u8>,
        evm_signature: Vec<u8>,
    },
}

impl Op {
    /// Build a contract call from typed arguments. Any native value the call
    /// transfers rides in `Transaction.amount`, not in this opcode.
    pub fn call(contract: [u8; 32], method: &str, args: &[CallArg]) -> Result<Self> {
        let calldata = encode_calldata(args)?;
        Ok(Self::CallContractArgs {
            contract,
            method: method.as_bytes().to_vec(),
            args: args.iter().map(|a| a.as_i64().unwrap_or(0)).collect(),
            calldata,
        })
    }

    /// Bincode bytes of this single enum value (discriminant + fields).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Op::Stake { validator, amount } => {
                out.extend_from_slice(&OP_STAKE.to_le_bytes());
                out.extend_from_slice(validator);
                out.extend_from_slice(&amount.to_le_bytes());
            }
            Op::Unjail { validator } => {
                out.extend_from_slice(&OP_UNJAIL.to_le_bytes());
                out.extend_from_slice(validator);
            }
            Op::CallContractArgs {
                contract,
                method,
                args,
                calldata,
            } => {
                out.extend_from_slice(&OP_CALL_CONTRACT_ARGS.to_le_bytes());
                out.extend_from_slice(contract);
                out.extend_from_slice(&(method.len() as u64).to_le_bytes());
                out.extend_from_slice(method);
                out.extend_from_slice(&(args.len() as u64).to_le_bytes());
                for a in args {
                    out.extend_from_slice(&a.to_le_bytes());
                }
                out.extend_from_slice(&(calldata.len() as u64).to_le_bytes());
                out.extend_from_slice(calldata);
            }
            Op::GovPropose {
                proposal_id,
                title,
                action,
                height_observed,
            } => {
                out.extend_from_slice(&OP_GOV_PROPOSE.to_le_bytes());
                out.extend_from_slice(&proposal_id.to_le_bytes());
                put_string(&mut out, title);
                out.extend_from_slice(&action.encode());
                out.extend_from_slice(&height_observed.to_le_bytes());
            }
            Op::GovVote {
                proposal_id,
                choice,
                height_observed,
            } => {
                out.extend_from_slice(&OP_GOV_VOTE.to_le_bytes());
                out.extend_from_slice(&proposal_id.to_le_bytes());
                out.extend_from_slice(&choice.encode());
                out.extend_from_slice(&height_observed.to_le_bytes());
            }
            Op::EvmCarrier {
                chain_id,
                evm_tx,
                evm_address,
                pq_pubkey,
                evm_signature,
            } => {
                out.extend_from_slice(&OP_EVM_CARRIER.to_le_bytes());
                put_u64(&mut out, *chain_id);
                put_vec(&mut out, evm_tx);
                out.extend_from_slice(evm_address);
                put_vec(&mut out, pq_pubkey);
                put_vec(&mut out, evm_signature);
            }
            Op::BindEvmAddress {
                chain_id,
                evm_address,
                pq_pubkey,
                binding_signature,
                evm_signature,
            } => {
                out.extend_from_slice(&OP_BIND_EVM_ADDRESS.to_le_bytes());
                put_u64(&mut out, *chain_id);
                out.extend_from_slice(evm_address);
                put_vec(&mut out, pq_pubkey);
                put_vec(&mut out, binding_signature);
                put_vec(&mut out, evm_signature);
            }
        }
        out
    }

    /// Execution gas, from the node's `opcode_gas` table
    /// (`stellereum/src/svm.rs:355-440`).
    pub fn gas(&self) -> u64 {
        match self {
            Op::Stake { .. } => GAS_STAKE_BOND,
            Op::Unjail { .. } => GAS_STAKE_UNBOND,
            Op::GovPropose { .. } => GAS_GOV_PROPOSE,
            Op::GovVote { .. } => GAS_GOV_VOTE,
            Op::EvmCarrier {
                evm_tx,
                pq_pubkey,
                evm_signature,
                ..
            } => GAS_EVM_CARRIER_BASE
                .saturating_add(pq_verify_gas(pq_pubkey.len(), 32, evm_signature.len()))
                .saturating_add((evm_tx.len() as u64).saturating_mul(GAS_PQ_VERIFY_PER_BYTE)),
            Op::BindEvmAddress {
                pq_pubkey,
                binding_signature,
                ..
            } => GAS_EVM_CARRIER_BASE.saturating_add(pq_verify_gas(
                pq_pubkey.len(),
                32,
                binding_signature.len(),
            )),
            Op::CallContractArgs {
                method,
                args,
                calldata,
                ..
            } => GAS_CONTRACT_CALL
                .saturating_add((args.len() as u64).saturating_mul(GAS_CONTRACT_CALL_PER_ARG))
                .saturating_add(
                    ((method.len().saturating_add(calldata.len())) as u64)
                        .saturating_mul(GAS_CONTRACT_CALL_PER_BYTE),
                ),
        }
    }
}

/// `pq_verify_gas(pubkey_len, message_len, signature_len)`
/// (`stellereum/src/svm.rs`).
pub fn pq_verify_gas(pubkey_len: usize, message_len: usize, signature_len: usize) -> u64 {
    let wire_bytes = (pubkey_len as u64)
        .saturating_add(message_len as u64)
        .saturating_add(signature_len as u64);
    GAS_PQ_VERIFY_BASE.saturating_add(wire_bytes.saturating_mul(GAS_PQ_VERIFY_PER_BYTE))
}

/// Encode a whole payload (`Vec<OpCode>`): `u64 LE count || op*`.
pub fn encode_payload(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + ops.len() * 40);
    out.extend_from_slice(&(ops.len() as u64).to_le_bytes());
    for op in ops {
        out.extend_from_slice(&op.encode());
    }
    out
}

/// Sum of the per-opcode gas costs.
pub fn payload_gas(ops: &[Op]) -> u64 {
    ops.iter()
        .fold(0u64, |acc, op| acc.saturating_add(op.gas()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calldata_layout() {
        let bytes = encode_calldata(&[
            CallArg::U64(7),
            CallArg::Bool(true),
            CallArg::String("hi".into()),
        ])
        .unwrap();
        assert_eq!(&bytes[..4], &3u32.to_le_bytes());
        assert_eq!(bytes[4], 0x02);
        assert_eq!(&bytes[5..13], &7u64.to_be_bytes());
        assert_eq!(bytes[13], 0x04);
        assert_eq!(bytes[14], 1);
        assert_eq!(bytes[15], 0x07);
        assert_eq!(&bytes[16..20], &2u32.to_le_bytes());
        assert_eq!(&bytes[20..22], b"hi");
    }

    #[test]
    fn r2x_abi_arg_ceiling_matches_the_vm() {
        // The VM accepts at most 8 scalar arguments (MAX_CONTRACT_CALL_ARGS)
        // and the manifest validator caps a method at the same 8.
        assert_eq!(MAX_ABI_ARGS, 8);

        let eight: Vec<CallArg> = (0..8u64).map(CallArg::U64).collect();
        assert!(encode_calldata(&eight).is_ok());
        assert!(Op::call([0u8; 32], "f", &eight).is_ok());

        let nine: Vec<CallArg> = (0..9u64).map(CallArg::U64).collect();
        assert!(matches!(
            encode_calldata(&nine),
            Err(SdkError::InvalidArgument(_))
        ));
        assert!(matches!(
            Op::call([0u8; 32], "f", &nine),
            Err(SdkError::InvalidArgument(_))
        ));
    }
}
