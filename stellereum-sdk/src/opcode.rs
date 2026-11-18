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

/// Bincode discriminant of `OpCode::SysCallStake`
/// (`stellereum/src/svm.rs:548`, 22nd variant).
pub const OP_STAKE: u32 = 21;
/// Bincode discriminant of `OpCode::SysCallCallContractArgs`
/// (`stellereum/src/svm.rs:994`).
pub const OP_CALL_CONTRACT_ARGS: u32 = 50;
/// Bincode discriminant of `OpCode::SysCallUnjail`
/// (`stellereum/src/svm.rs:1124`).
pub const OP_UNJAIL: u32 = 56;

/// `GAS_BASIC_TRANSFER` (`stellereum/src/svm.rs:36`).
pub const GAS_BASIC_TRANSFER: u64 = 280_000;
/// `GAS_STAKE_BOND` (`stellereum/src/svm.rs:92`).
pub const GAS_STAKE_BOND: u64 = 2_000;
/// `GAS_STAKE_UNBOND` (`stellereum/src/svm.rs:94`).
pub const GAS_STAKE_UNBOND: u64 = 800;
/// `GAS_CONTRACT_CALL` (`stellereum/src/svm.rs:63`).
pub const GAS_CONTRACT_CALL: u64 = 1_000;
/// `GAS_CONTRACT_CALL_PER_ARG` (`stellereum/src/svm.rs:65`).
pub const GAS_CONTRACT_CALL_PER_ARG: u64 = 10;
/// `GAS_CONTRACT_CALL_PER_BYTE` (`stellereum/src/svm.rs:70`).
pub const GAS_CONTRACT_CALL_PER_BYTE: u64 = 2;

/// Maximum ABI arguments (`stellereum/src/contract_abi.rs:62`).
pub const MAX_ABI_ARGS: usize = 16;
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
        }
        out
    }

    /// Execution gas, from the node's `opcode_gas` table
    /// (`stellereum/src/svm.rs:355-440`).
    pub fn gas(&self) -> u64 {
        match self {
            Op::Stake { .. } => GAS_STAKE_BOND,
            Op::Unjail { .. } => GAS_STAKE_UNBOND,
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
}
