//! Typed contract ABI: multi-argument methods, typed returns, typed events and
//! a stable JSON manifest plus a canonical binary encoding.
//!
//! # Why
//!
//! The original contract ABI was a single `(i64) -> i64` export, which forced
//! every multi-parameter contract to pack its arguments by hand
//! (`from * 100_000_000 + to * 100_000 + amount`). Packing is lossy, ambiguous
//! (it cannot express negative/large values, addresses or blobs) and it puts
//! the encoding knowledge in *every* client instead of in one place.
//!
//! This module replaces that with a real ABI:
//!
//! * a **JSON manifest** (`ContractAbi`) describing every method
//!   (`name`, typed `params`, typed `returns`, `mutates_state`) and every event
//!   (`name`, typed `topics`, typed `data`);
//! * a **canonical binary encoding** for arguments, return values and events
//!   that is length-prefixed, order-stable and self-describing;
//! * **typed values** (`AbiValue`) so a client never has to guess whether a
//!   number is an `i64`, a `u64` or a `bool`.
//!
//! The model follows Near (JSON ABI + codegen), MultiversX (JSON ABI -> SDK
//! typing + event decoding) and TON (Blueprint/Tolk ABI), while staying
//! byte-compatible with nothing else on purpose: the format is versioned by
//! the type tags below, which are frozen forever.
//!
//! # Wire format ("STELL-ABI v1")
//!
//! ```text
//! args_payload := u32_le(arg_count) || arg_0 || arg_1 || ...
//! arg_i       := u8(type_tag) || value_payload
//!
//! calldata     := u32_le(selector) || args_payload
//! selector     := sha256(method_name)[0..4] read as u32_le
//!
//! return_value := u8(type_tag) || value_payload
//!
//! event_payload := u32_le(topic_count) || topic_0 || ... || u32_le(data_count) || data_0 || ...
//!
//! value_payload per type (type tags are frozen, never renumbered):
//!   I64     0x01 : 8 bytes, big-endian two's complement
//!   U64     0x02 : 8 bytes, big-endian
//!   I32     0x03 : 4 bytes, big-endian two's complement
//!   Bool    0x04 : 1 byte, 0x00 = false, 0x01 = true
//!   Bytes   0x05 : u32_le(len) || len raw bytes
//!   Address 0x06 : 32 raw bytes
//!   String  0x07 : u32_le(len) || len UTF-8 bytes
//! ```
//!
//! Big-endian is used for fixed-width integers so that the byte order does not
//! depend on the host architecture — a consensus chain cannot afford
//! host-dependent encodings. Variable-length payloads are length-prefixed with
//! a little-endian `u32` so a decoder can skip a value without knowing its
//! type in advance.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;
use std::fmt;

/// Maximum number of arguments accepted by a single ABI-encoded call.
pub const MAX_ABI_ARGS: usize = 16;
/// Maximum size (bytes) of a single length-prefixed blob (`bytes` / `string`).
pub const MAX_ABI_BLOB_LEN: usize = 1024 * 1024;

/// Stable binary type tag for [`AbiType::I64`].
pub const ABI_TAG_I64: u8 = 0x01;
/// Stable binary type tag for [`AbiType::U64`].
pub const ABI_TAG_U64: u8 = 0x02;
/// Stable binary type tag for [`AbiType::I32`].
pub const ABI_TAG_I32: u8 = 0x03;
/// Stable binary type tag for [`AbiType::Bool`].
pub const ABI_TAG_BOOL: u8 = 0x04;
/// Stable binary type tag for [`AbiType::Bytes`].
pub const ABI_TAG_BYTES: u8 = 0x05;
/// Stable binary type tag for [`AbiType::Address`].
pub const ABI_TAG_ADDRESS: u8 = 0x06;
/// Stable binary type tag for [`AbiType::String`].
pub const ABI_TAG_STRING: u8 = 0x07;

/// Length in bytes of an on-chain address.
pub const ABI_ADDRESS_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A type supported by the contract ABI.
///
/// The set is deliberately small and closed: every type has a stable binary
/// encoding (see [`AbiType::tag`]) and a stable JSON name (see
/// [`AbiType::as_str`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AbiType {
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 32-bit integer.
    I32,
    /// Boolean.
    Bool,
    /// Opaque byte blob.
    Bytes,
    /// 32-byte account address.
    Address,
    /// UTF-8 string.
    String,
}

impl AbiType {
    /// Every supported type, in canonical order.
    pub const ALL: [AbiType; 7] = [
        AbiType::I64,
        AbiType::U64,
        AbiType::I32,
        AbiType::Bool,
        AbiType::Bytes,
        AbiType::Address,
        AbiType::String,
    ];

    /// The stable binary type tag of this type. Part of the wire format.
    pub const fn tag(self) -> u8 {
        match self {
            AbiType::I64 => ABI_TAG_I64,
            AbiType::U64 => ABI_TAG_U64,
            AbiType::I32 => ABI_TAG_I32,
            AbiType::Bool => ABI_TAG_BOOL,
            AbiType::Bytes => ABI_TAG_BYTES,
            AbiType::Address => ABI_TAG_ADDRESS,
            AbiType::String => ABI_TAG_STRING,
        }
    }

    /// Reverse of [`AbiType::tag`].
    pub const fn from_tag(tag: u8) -> Option<AbiType> {
        match tag {
            ABI_TAG_I64 => Some(AbiType::I64),
            ABI_TAG_U64 => Some(AbiType::U64),
            ABI_TAG_I32 => Some(AbiType::I32),
            ABI_TAG_BOOL => Some(AbiType::Bool),
            ABI_TAG_BYTES => Some(AbiType::Bytes),
            ABI_TAG_ADDRESS => Some(AbiType::Address),
            ABI_TAG_STRING => Some(AbiType::String),
            _ => None,
        }
    }

    /// The stable JSON name of this type (`"i64"`, `"u64"`, ...).
    pub const fn as_str(self) -> &'static str {
        match self {
            AbiType::I64 => "i64",
            AbiType::U64 => "u64",
            AbiType::I32 => "i32",
            AbiType::Bool => "bool",
            AbiType::Bytes => "bytes",
            AbiType::Address => "address",
            AbiType::String => "string",
        }
    }

    /// Parse a type name. Case-insensitive and tolerant of the usual aliases
    /// (`"I64"`, `"i64"`, `"int64"`, `"bytes"`, `"byte[]"`, `"hex"`, ...).
    pub fn parse(s: &str) -> Option<AbiType> {
        let norm = s.trim().to_ascii_lowercase();
        match norm.as_str() {
            "i64" | "int64" | "int" | "long" | "number" => Some(AbiType::I64),
            "u64" | "uint64" | "uint" | "unsigned" => Some(AbiType::U64),
            "i32" | "int32" => Some(AbiType::I32),
            "bool" | "boolean" => Some(AbiType::Bool),
            "bytes" | "byte" | "byte[]" | "blob" | "hex" | "u8[]" => Some(AbiType::Bytes),
            "address" | "addr" | "account" | "accountid" | "account_id" | "public_key" => {
                Some(AbiType::Address)
            }
            "string" | "str" | "text" | "utf8" => Some(AbiType::String),
            _ => None,
        }
    }

    /// `true` for variable-length types (`bytes`, `string`).
    pub const fn is_variable(self) -> bool {
        matches!(self, AbiType::Bytes | AbiType::String)
    }

    /// `true` for types that are opaque blobs rather than scalars.
    pub const fn is_blob(self) -> bool {
        matches!(self, AbiType::Bytes | AbiType::Address | AbiType::String)
    }

    /// Fixed encoded size in bytes, or `None` for variable-length types.
    pub const fn fixed_size(self) -> Option<usize> {
        match self {
            AbiType::I64 | AbiType::U64 => Some(8),
            AbiType::I32 => Some(4),
            AbiType::Bool => Some(1),
            AbiType::Address => Some(32),
            AbiType::Bytes | AbiType::String => None,
        }
    }

    /// `true` when the type can be carried by an `i64` wasm parameter
    /// (the runtime's native calling convention).
    pub const fn is_wasm_scalar(self) -> bool {
        matches!(
            self,
            AbiType::I64 | AbiType::U64 | AbiType::I32 | AbiType::Bool
        )
    }
}

impl fmt::Display for AbiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for AbiType {
    type Err = AbiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AbiType::parse(s).ok_or_else(|| AbiError::Json(format!("unknown ABI type: {s}")))
    }
}

impl Serialize for AbiType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AbiType {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(d)?;
        let name = match raw {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        };
        AbiType::parse(&name).ok_or_else(|| D::Error::custom(format!("unknown ABI type: {name}")))
    }
}

/// A named, typed parameter of a method or event field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiParam {
    /// Parameter name (as written by the contract author).
    pub name: String,
    /// Parameter type.
    #[serde(rename = "type", alias = "ty")]
    pub ty: AbiType,
}

impl AbiParam {
    /// Build a parameter.
    pub fn new(name: impl Into<String>, ty: AbiType) -> Self {
        Self {
            name: name.into(),
            ty,
        }
    }
}

/// A callable method exported by a contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiMethod {
    /// Export name in the wasm module.
    pub name: String,
    /// Ordered parameters.
    #[serde(default)]
    pub params: Vec<AbiParam>,
    /// Declared return type.
    ///
    /// Methods whose wasm export returns nothing are modelled with
    /// [`AbiType::I64`] and a return value of `0`.
    #[serde(default = "default_return_type")]
    pub returns: AbiType,
    /// Whether the method mutates contract state (view methods do not).
    #[serde(default)]
    pub mutates_state: bool,
}

fn default_return_type() -> AbiType {
    AbiType::I64
}

impl AbiMethod {
    /// Build a method descriptor.
    pub fn new(
        name: impl Into<String>,
        params: Vec<AbiParam>,
        returns: AbiType,
        mutates_state: bool,
    ) -> Self {
        Self {
            name: name.into(),
            params,
            returns,
            mutates_state,
        }
    }

    /// A read-only (view) method.
    pub fn view(name: impl Into<String>, params: Vec<AbiParam>, returns: AbiType) -> Self {
        Self::new(name, params, returns, false)
    }

    /// A state-mutating method.
    pub fn mutating(name: impl Into<String>, params: Vec<AbiParam>, returns: AbiType) -> Self {
        Self::new(name, params, returns, true)
    }

    /// Number of declared parameters.
    pub fn arity(&self) -> usize {
        self.params.len()
    }
}

/// An event emitted by a contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiEvent {
    /// Event name.
    pub name: String,
    /// Indexed fields, in order.
    #[serde(default)]
    pub topics: Vec<AbiParam>,
    /// Non-indexed fields, in order.
    #[serde(default)]
    pub data: Vec<AbiParam>,
}

impl AbiEvent {
    /// Build an event descriptor.
    pub fn new(name: impl Into<String>, topics: Vec<AbiParam>, data: Vec<AbiParam>) -> Self {
        Self {
            name: name.into(),
            topics,
            data,
        }
    }
}

/// The ABI manifest of a contract: every method and every event it exposes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAbi {
    /// Methods exported by the contract.
    #[serde(default)]
    pub methods: Vec<AbiMethod>,
    /// Events emitted by the contract.
    #[serde(default)]
    pub events: Vec<AbiEvent>,
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// A typed ABI value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiValue {
    /// Signed 64-bit integer.
    I64(i64),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Signed 32-bit integer.
    I32(i32),
    /// Boolean.
    Bool(bool),
    /// Opaque byte blob.
    Bytes(Vec<u8>),
    /// 32-byte address.
    Address([u8; 32]),
    /// UTF-8 string.
    String(String),
}

impl AbiValue {
    /// The ABI type of this value.
    pub fn abi_type(&self) -> AbiType {
        match self {
            AbiValue::I64(_) => AbiType::I64,
            AbiValue::U64(_) => AbiType::U64,
            AbiValue::I32(_) => AbiType::I32,
            AbiValue::Bool(_) => AbiType::Bool,
            AbiValue::Bytes(_) => AbiType::Bytes,
            AbiValue::Address(_) => AbiType::Address,
            AbiValue::String(_) => AbiType::String,
        }
    }

    /// Numeric view of a scalar value (`i64`, `u64`, `i32`, `bool`).
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            AbiValue::I64(v) => Some(*v),
            AbiValue::U64(v) => Some(*v as i64),
            AbiValue::I32(v) => Some(*v as i64),
            AbiValue::Bool(v) => Some(if *v { 1 } else { 0 }),
            _ => None,
        }
    }

    /// Unsigned numeric view of a scalar value.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_i64().map(|v| v as u64)
    }

    /// Boolean view of a scalar value.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AbiValue::Bool(v) => Some(*v),
            AbiValue::I64(v) => Some(*v != 0),
            AbiValue::U64(v) => Some(*v != 0),
            AbiValue::I32(v) => Some(*v != 0),
            _ => None,
        }
    }

    /// Byte view of a blob value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            AbiValue::Bytes(b) => Some(b.as_slice()),
            AbiValue::Address(a) => Some(a.as_slice()),
            AbiValue::String(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// Address view of the value.
    pub fn as_address(&self) -> Option<[u8; 32]> {
        match self {
            AbiValue::Address(a) => Some(*a),
            _ => None,
        }
    }

    /// String view of the value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AbiValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Convert the value to the requested type when the conversion is
    /// lossless. Used by the RPC layer so that a JSON `5` may satisfy a `u64`
    /// parameter.
    pub fn coerce_to(&self, ty: AbiType) -> Result<AbiValue, AbiError> {
        if self.abi_type() == ty {
            return Ok(self.clone());
        }
        let coerced = match (self, ty) {
            (AbiValue::I64(v), AbiType::U64) => {
                if *v < 0 {
                    return Err(AbiError::ValueOutOfRange { ty });
                }
                AbiValue::U64(*v as u64)
            }
            (AbiValue::I64(v), AbiType::I32) => {
                if *v < i32::MIN as i64 || *v > i32::MAX as i64 {
                    return Err(AbiError::ValueOutOfRange { ty });
                }
                AbiValue::I32(*v as i32)
            }
            (AbiValue::I64(v), AbiType::Bool) => AbiValue::Bool(*v != 0),
            (AbiValue::U64(v), AbiType::I64) => {
                if *v > i64::MAX as u64 {
                    return Err(AbiError::ValueOutOfRange { ty });
                }
                AbiValue::I64(*v as i64)
            }
            (AbiValue::U64(v), AbiType::I32) => {
                if *v > i32::MAX as u64 {
                    return Err(AbiError::ValueOutOfRange { ty });
                }
                AbiValue::I32(*v as i32)
            }
            (AbiValue::U64(v), AbiType::Bool) => AbiValue::Bool(*v != 0),
            (AbiValue::I32(v), AbiType::I64) => AbiValue::I64(*v as i64),
            (AbiValue::I32(v), AbiType::U64) => AbiValue::U64(*v as u64),
            (AbiValue::I32(v), AbiType::Bool) => AbiValue::Bool(*v != 0),
            (AbiValue::Bool(v), AbiType::I64) => AbiValue::I64(if *v { 1 } else { 0 }),
            (AbiValue::Bool(v), AbiType::U64) => AbiValue::U64(if *v { 1 } else { 0 }),
            (AbiValue::Bool(v), AbiType::I32) => AbiValue::I32(if *v { 1 } else { 0 }),
            _ => {
                return Err(AbiError::TypeMismatch {
                    method: String::new(),
                    index: 0,
                    expected: ty,
                    got: self.abi_type(),
                })
            }
        };
        Ok(coerced)
    }

    /// Encode the value with its type tag: `u8(tag) || value_payload`.
    pub fn encode(&self) -> Result<Vec<u8>, AbiError> {
        let mut out = Vec::with_capacity(9);
        out.push(self.abi_type().tag());
        out.extend_from_slice(&self.encode_payload()?);
        Ok(out)
    }

    /// Encode only the value payload (without the type tag).
    pub fn encode_payload(&self) -> Result<Vec<u8>, AbiError> {
        match self {
            AbiValue::I64(v) => Ok(v.to_be_bytes().to_vec()),
            AbiValue::U64(v) => Ok(v.to_be_bytes().to_vec()),
            AbiValue::I32(v) => Ok(v.to_be_bytes().to_vec()),
            AbiValue::Bool(v) => Ok(vec![if *v { 1 } else { 0 }]),
            AbiValue::Bytes(b) => {
                if b.len() > MAX_ABI_BLOB_LEN {
                    return Err(AbiError::LengthTooLarge { len: b.len() });
                }
                let mut out = Vec::with_capacity(4 + b.len());
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
                Ok(out)
            }
            AbiValue::Address(a) => Ok(a.to_vec()),
            AbiValue::String(s) => {
                let b = s.as_bytes();
                if b.len() > MAX_ABI_BLOB_LEN {
                    return Err(AbiError::LengthTooLarge { len: b.len() });
                }
                let mut out = Vec::with_capacity(4 + b.len());
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
                Ok(out)
            }
        }
    }

    /// Decode a tagged value (`u8(tag) || payload`).
    pub fn decode_tagged(bytes: &[u8]) -> Result<AbiValue, AbiError> {
        if bytes.is_empty() {
            return Err(AbiError::BufferTooShort { needed: 1, got: 0 });
        }
        let ty = AbiType::from_tag(bytes[0]).ok_or(AbiError::UnknownTypeTag(bytes[0]))?;
        let mut cur = Cursor::new(&bytes[1..]);
        let v = AbiValue::decode_payload(ty, &mut cur)?;
        Ok(v)
    }

    /// Decode a value payload of the given type from a cursor.
    pub fn decode_payload(ty: AbiType, cur: &mut Cursor<'_>) -> Result<AbiValue, AbiError> {
        match ty {
            AbiType::I64 => {
                let b = cur.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                Ok(AbiValue::I64(i64::from_be_bytes(a)))
            }
            AbiType::U64 => {
                let b = cur.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                Ok(AbiValue::U64(u64::from_be_bytes(a)))
            }
            AbiType::I32 => {
                let b = cur.take(4)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(b);
                Ok(AbiValue::I32(i32::from_be_bytes(a)))
            }
            AbiType::Bool => {
                let b = cur.take(1)?;
                match b[0] {
                    0 => Ok(AbiValue::Bool(false)),
                    1 => Ok(AbiValue::Bool(true)),
                    other => Err(AbiError::InvalidBool(other)),
                }
            }
            AbiType::Bytes => {
                let len = cur.read_u32_le()? as usize;
                if len > MAX_ABI_BLOB_LEN {
                    return Err(AbiError::LengthTooLarge { len });
                }
                let b = cur.take(len)?;
                Ok(AbiValue::Bytes(b.to_vec()))
            }
            AbiType::Address => {
                let b = cur.take(ABI_ADDRESS_LEN)?;
                let mut a = [0u8; 32];
                a.copy_from_slice(b);
                Ok(AbiValue::Address(a))
            }
            AbiType::String => {
                let len = cur.read_u32_le()? as usize;
                if len > MAX_ABI_BLOB_LEN {
                    return Err(AbiError::LengthTooLarge { len });
                }
                let b = cur.take(len)?;
                let s = std::str::from_utf8(b).map_err(|_| AbiError::InvalidUtf8)?;
                Ok(AbiValue::String(s.to_string()))
            }
        }
    }

    /// JSON representation of the value (hex strings for blobs).
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            AbiValue::I64(v) => serde_json::Value::from(*v),
            AbiValue::U64(v) => serde_json::Value::from(*v),
            AbiValue::I32(v) => serde_json::Value::from(*v),
            AbiValue::Bool(v) => serde_json::Value::Bool(*v),
            AbiValue::Bytes(b) => serde_json::Value::String(format!("0x{}", hex::encode(b))),
            AbiValue::Address(a) => serde_json::Value::String(format!("0x{}", hex::encode(a))),
            AbiValue::String(s) => serde_json::Value::String(s.clone()),
        }
    }

    /// Parse a JSON value into a typed ABI value.
    pub fn from_json_value(v: &serde_json::Value) -> Result<AbiValue, AbiError> {
        match v {
            serde_json::Value::Bool(b) => Ok(AbiValue::Bool(*b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(AbiValue::I64(i))
                } else if let Some(u) = n.as_u64() {
                    Ok(AbiValue::U64(u))
                } else {
                    Err(AbiError::Json(format!("number out of range: {n}")))
                }
            }
            serde_json::Value::String(s) => {
                let t = s.trim();
                if t.eq_ignore_ascii_case("true") {
                    return Ok(AbiValue::Bool(true));
                }
                if t.eq_ignore_ascii_case("false") {
                    return Ok(AbiValue::Bool(false));
                }
                if t.starts_with("0x") || t.starts_with("0X") {
                    let raw = hex::decode(&t[2..])
                        .map_err(|e| AbiError::Json(format!("invalid hex: {e}")))?;
                    // A 32-byte blob is an address, anything else is bytes.
                    if raw.len() == ABI_ADDRESS_LEN {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&raw);
                        return Ok(AbiValue::Address(a));
                    }
                    return Ok(AbiValue::Bytes(raw));
                }
                if let Ok(i) = t.parse::<i64>() {
                    return Ok(AbiValue::I64(i));
                }
                if let Ok(u) = t.parse::<u64>() {
                    return Ok(AbiValue::U64(u));
                }
                Ok(AbiValue::String(s.clone()))
            }
            serde_json::Value::Array(items) => {
                let mut bytes = Vec::with_capacity(items.len());
                for it in items {
                    let n = it.as_u64().filter(|n| *n <= 255).ok_or_else(|| {
                        AbiError::Json("byte array must contain 0..=255".to_string())
                    })?;
                    bytes.push(n as u8);
                }
                Ok(AbiValue::Bytes(bytes))
            }
            serde_json::Value::Null => {
                Err(AbiError::Json("null is not a valid ABI value".to_string()))
            }
            other => Err(AbiError::Json(format!(
                "cannot convert {other} into an ABI value"
            ))),
        }
    }
}

impl Serialize for AbiValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json_value().serialize(s)
    }
}

impl<'de> Deserialize<'de> for AbiValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        AbiValue::from_json_value(&v).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by ABI encoding / decoding / manifest parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// The method is not declared in the manifest.
    UnknownMethod(String),
    /// The event is not declared in the manifest.
    UnknownEvent(String),
    /// The number of arguments does not match the declaration.
    ArityMismatch {
        /// Method name.
        method: String,
        /// Expected argument count.
        expected: usize,
        /// Supplied argument count.
        got: usize,
    },
    /// An argument has a different type than declared.
    TypeMismatch {
        /// Method name (empty when the error is not method-scoped).
        method: String,
        /// Argument index.
        index: usize,
        /// Declared type.
        expected: AbiType,
        /// Supplied type.
        got: AbiType,
    },
    /// The encoded type tag does not match the declared type.
    UnexpectedTypeTag {
        /// Argument index.
        index: usize,
        /// Declared type.
        expected: AbiType,
        /// Tag found on the wire.
        tag: u8,
    },
    /// The type tag is not part of the ABI.
    UnknownTypeTag(u8),
    /// The buffer ended before the value was complete.
    BufferTooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
    /// Extra bytes remained after decoding.
    TrailingBytes {
        /// Number of unexpected bytes.
        got: usize,
    },
    /// The boolean byte was neither `0x00` nor `0x01`.
    InvalidBool(u8),
    /// A string payload was not valid UTF-8.
    InvalidUtf8,
    /// A length prefix exceeded the maximum blob size.
    LengthTooLarge {
        /// The offending length.
        len: usize,
    },
    /// The value does not fit the requested type.
    ValueOutOfRange {
        /// The target type.
        ty: AbiType,
    },
    /// The manifest could not be parsed.
    Json(String),
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
            AbiError::UnknownEvent(e) => write!(f, "unknown event: {e}"),
            AbiError::ArityMismatch {
                method,
                expected,
                got,
            } => write!(
                f,
                "argument count mismatch for {method}: expected {expected}, got {got}"
            ),
            AbiError::TypeMismatch {
                method,
                index,
                expected,
                got,
            } => {
                if method.is_empty() {
                    write!(
                        f,
                        "type mismatch at index {index}: expected {expected}, got {got}"
                    )
                } else {
                    write!(
                        f,
                        "type mismatch for {method} at index {index}: expected {expected}, got {got}"
                    )
                }
            }
            AbiError::UnexpectedTypeTag {
                index,
                expected,
                tag,
            } => write!(
                f,
                "unexpected type tag 0x{tag:02x} at index {index}: expected {expected}"
            ),
            AbiError::UnknownTypeTag(tag) => write!(f, "unknown ABI type tag: 0x{tag:02x}"),
            AbiError::BufferTooShort { needed, got } => {
                write!(f, "buffer too short: needed {needed} bytes, got {got}")
            }
            AbiError::TrailingBytes { got } => write!(f, "{got} unexpected trailing bytes"),
            AbiError::InvalidBool(b) => write!(f, "invalid boolean byte: 0x{b:02x}"),
            AbiError::InvalidUtf8 => write!(f, "string payload is not valid UTF-8"),
            AbiError::LengthTooLarge { len } => write!(f, "blob length {len} exceeds the maximum"),
            AbiError::ValueOutOfRange { ty } => write!(f, "value does not fit into {ty}"),
            AbiError::Json(m) => write!(f, "invalid ABI manifest: {m}"),
        }
    }
}

impl std::error::Error for AbiError {}

impl From<serde_json::Error> for AbiError {
    fn from(e: serde_json::Error) -> Self {
        AbiError::Json(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

/// A tiny bounds-checked reader over a byte slice.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Wrap a byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes left.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// `true` when the whole input was consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8, AbiError> {
        let b = self.take(1)?;
        Ok(b[0])
    }

    /// Read a little-endian `u32`.
    pub fn read_u32_le(&mut self) -> Result<u32, AbiError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `u32` and return it as `usize`.
    pub fn read_len(&mut self) -> Result<usize, AbiError> {
        let n = self.read_u32_le()? as usize;
        if n > MAX_ABI_BLOB_LEN {
            return Err(AbiError::LengthTooLarge { len: n });
        }
        Ok(n)
    }

    /// Borrow the next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], AbiError> {
        if self.remaining() < n {
            return Err(AbiError::BufferTooShort {
                needed: n,
                got: self.remaining(),
            });
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ContractAbi
// ---------------------------------------------------------------------------

impl ContractAbi {
    /// An empty manifest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a method by name.
    pub fn method(&self, name: &str) -> Option<&AbiMethod> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// Look up an event by name.
    pub fn event(&self, name: &str) -> Option<&AbiEvent> {
        self.events.iter().find(|e| e.name == name)
    }

    /// Names of every declared method.
    pub fn method_names(&self) -> Vec<&str> {
        self.methods.iter().map(|m| m.name.as_str()).collect()
    }

    /// Names of every declared event.
    pub fn event_names(&self) -> Vec<&str> {
        self.events.iter().map(|e| e.name.as_str()).collect()
    }

    /// Append a method.
    pub fn add_method(&mut self, m: AbiMethod) -> &mut Self {
        self.methods.push(m);
        self
    }

    /// Append an event.
    pub fn add_event(&mut self, e: AbiEvent) -> &mut Self {
        self.events.push(e);
        self
    }

    /// Serialize the manifest to compact JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"methods\":[],\"events\":[]}".to_string())
    }

    /// Serialize the manifest to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{\n  \"methods\": [],\n  \"events\": []\n}".to_string())
    }

    /// Parse a JSON manifest.
    pub fn from_json<S: AsRef<str>>(s: S) -> Result<Self, AbiError> {
        let text = s.as_ref();
        let value: serde_json::Value = serde_json::from_str(text).map_err(AbiError::from)?;
        ContractAbi::from_json_value(&value)
    }

    /// Parse a JSON manifest from an already-parsed value.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, AbiError> {
        // Accept both a bare manifest and a manifest wrapped in
        // `{"abi": {...}}` (how some toolchains ship it).
        let root = match value.get("abi") {
            Some(inner) if inner.is_object() => inner,
            _ => value,
        };
        let abi: ContractAbi = serde_json::from_value(root.clone()).map_err(AbiError::from)?;
        abi.validate()?;
        Ok(abi)
    }

    /// JSON value of the manifest.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// Sanity-check the manifest: unique names, sane arities.
    pub fn validate(&self) -> Result<(), AbiError> {
        let mut seen: Vec<&str> = Vec::with_capacity(self.methods.len());
        for m in &self.methods {
            if seen.contains(&m.name.as_str()) {
                return Err(AbiError::Json(format!("duplicate method: {}", m.name)));
            }
            seen.push(&m.name);
            if m.params.len() > MAX_ABI_ARGS {
                return Err(AbiError::Json(format!(
                    "method {} declares {} parameters, the maximum is {MAX_ABI_ARGS}",
                    m.name,
                    m.params.len()
                )));
            }
        }
        let mut seen_events: Vec<&str> = Vec::with_capacity(self.events.len());
        for e in &self.events {
            if seen_events.contains(&e.name.as_str()) {
                return Err(AbiError::Json(format!("duplicate event: {}", e.name)));
            }
            seen_events.push(&e.name);
        }
        Ok(())
    }

    /// The 4-byte selector of a method name: `sha256(name)[0..4]` as `u32_le`.
    pub fn method_selector(name: &str) -> [u8; 4] {
        let digest = sha2::Sha256::digest(name.as_bytes());
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// Encode the arguments of a method call.
    ///
    /// The encoding is canonical: `u32_le(arg_count)` followed by one
    /// type-tagged, length-prefixed value per parameter, in declaration order.
    pub fn encode_args(&self, method: &str, args: &[AbiValue]) -> Result<Vec<u8>, AbiError> {
        let m = self
            .method(method)
            .ok_or_else(|| AbiError::UnknownMethod(method.to_string()))?;
        if m.params.len() != args.len() {
            return Err(AbiError::ArityMismatch {
                method: method.to_string(),
                expected: m.params.len(),
                got: args.len(),
            });
        }
        if args.len() > MAX_ABI_ARGS {
            return Err(AbiError::ArityMismatch {
                method: method.to_string(),
                expected: m.params.len(),
                got: args.len(),
            });
        }
        let mut out = Vec::with_capacity(4 + args.len() * 9);
        out.extend_from_slice(&(args.len() as u32).to_le_bytes());
        for (i, (p, v)) in m.params.iter().zip(args.iter()).enumerate() {
            let got = v.abi_type();
            if got != p.ty {
                return Err(AbiError::TypeMismatch {
                    method: method.to_string(),
                    index: i,
                    expected: p.ty,
                    got,
                });
            }
            out.push(p.ty.tag());
            out.extend_from_slice(&v.encode_payload()?);
        }
        Ok(out)
    }

    /// Decode the arguments of a method call.
    pub fn decode_args(&self, method: &str, bytes: &[u8]) -> Result<Vec<AbiValue>, AbiError> {
        let m = self
            .method(method)
            .ok_or_else(|| AbiError::UnknownMethod(method.to_string()))?;
        let mut cur = Cursor::new(bytes);
        let count = cur.read_u32_le()? as usize;
        if count != m.params.len() {
            return Err(AbiError::ArityMismatch {
                method: method.to_string(),
                expected: m.params.len(),
                got: count,
            });
        }
        let mut out = Vec::with_capacity(count);
        for (i, p) in m.params.iter().enumerate() {
            let tag = cur.read_u8()?;
            if tag != p.ty.tag() {
                return Err(AbiError::UnexpectedTypeTag {
                    index: i,
                    expected: p.ty,
                    tag,
                });
            }
            out.push(AbiValue::decode_payload(p.ty, &mut cur)?);
        }
        if !cur.is_empty() {
            return Err(AbiError::TrailingBytes {
                got: cur.remaining(),
            });
        }
        Ok(out)
    }

    /// Encode a return value for a method.
    pub fn encode_return(&self, method: &str, value: &AbiValue) -> Result<Vec<u8>, AbiError> {
        let m = self
            .method(method)
            .ok_or_else(|| AbiError::UnknownMethod(method.to_string()))?;
        let v = value.coerce_to(m.returns).map_err(|e| match e {
            AbiError::TypeMismatch {
                index,
                expected,
                got,
                ..
            } => AbiError::TypeMismatch {
                method: method.to_string(),
                index,
                expected,
                got,
            },
            other => other,
        })?;
        v.encode()
    }

    /// Decode a return value of a method.
    ///
    /// Accepts the canonical tagged encoding (`u8(tag) || payload`). For
    /// convenience it also accepts a bare payload: the fixed-width encoding of
    /// a scalar, or the length-prefixed encoding of a blob.
    pub fn decode_return(&self, method: &str, bytes: &[u8]) -> Result<AbiValue, AbiError> {
        let m = self
            .method(method)
            .ok_or_else(|| AbiError::UnknownMethod(method.to_string()))?;
        let ty = m.returns;

        // Canonical: type tag followed by the payload.
        if !bytes.is_empty() && bytes[0] == ty.tag() {
            let mut cur = Cursor::new(&bytes[1..]);
            let v = AbiValue::decode_payload(ty, &mut cur)?;
            if cur.is_empty() {
                return Ok(v);
            }
        }

        // Bare payload fallback.
        match ty {
            AbiType::I64 | AbiType::U64 | AbiType::I32 | AbiType::Bool | AbiType::Address => {
                let mut cur = Cursor::new(bytes);
                let v = AbiValue::decode_payload(ty, &mut cur)?;
                // Audit B-VM: strict — trailing bytes after a bare scalar
                // are a decode confusion vector (RPC/client misread).
                if !cur.is_empty() {
                    return Err(AbiError::TrailingBytes {
                        got: cur.remaining(),
                    });
                }
                Ok(v)
            }
            AbiType::Bytes | AbiType::String => {
                if bytes.len() >= 4 {
                    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                    if len == bytes.len() - 4 {
                        let mut cur = Cursor::new(&bytes[4..]);
                        return AbiValue::decode_payload(ty, &mut cur);
                    }
                }
                if ty == AbiType::String {
                    let s = std::str::from_utf8(bytes).map_err(|_| AbiError::InvalidUtf8)?;
                    return Ok(AbiValue::String(s.to_string()));
                }
                Ok(AbiValue::Bytes(bytes.to_vec()))
            }
        }
    }

    /// Encode a full call payload: `u32_le(selector) || args_payload`.
    pub fn encode_call(&self, method: &str, args: &[AbiValue]) -> Result<Vec<u8>, AbiError> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::method_selector(method));
        out.extend_from_slice(&self.encode_args(method, args)?);
        Ok(out)
    }

    /// Decode a full call payload into `(method, args)`.
    pub fn decode_call(&self, bytes: &[u8]) -> Result<(String, Vec<AbiValue>), AbiError> {
        if bytes.len() < 4 {
            return Err(AbiError::BufferTooShort {
                needed: 4,
                got: bytes.len(),
            });
        }
        let selector = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let method = self
            .methods
            .iter()
            .find(|m| Self::method_selector(&m.name) == selector)
            .map(|m| m.name.clone())
            .ok_or_else(|| AbiError::UnknownMethod(format!("0x{}", hex::encode(selector))))?;
        let args = self.decode_args(&method, &bytes[4..])?;
        Ok((method, args))
    }

    /// Validate a call against the manifest (method exists, arity and types).
    pub fn validate_args(&self, method: &str, args: &[AbiValue]) -> Result<(), AbiError> {
        let m = self
            .method(method)
            .ok_or_else(|| AbiError::UnknownMethod(method.to_string()))?;
        if m.params.len() != args.len() {
            return Err(AbiError::ArityMismatch {
                method: method.to_string(),
                expected: m.params.len(),
                got: args.len(),
            });
        }
        for (i, (p, v)) in m.params.iter().zip(args.iter()).enumerate() {
            let got = v.abi_type();
            if got != p.ty {
                return Err(AbiError::TypeMismatch {
                    method: method.to_string(),
                    index: i,
                    expected: p.ty,
                    got,
                });
            }
        }
        Ok(())
    }

    /// Encode an event payload: topics first, then data, each type-tagged.
    pub fn encode_event(
        &self,
        event: &str,
        topics: &[AbiValue],
        data: &[AbiValue],
    ) -> Result<Vec<u8>, AbiError> {
        let e = self
            .event(event)
            .ok_or_else(|| AbiError::UnknownEvent(event.to_string()))?;
        if e.topics.len() != topics.len() {
            return Err(AbiError::ArityMismatch {
                method: event.to_string(),
                expected: e.topics.len(),
                got: topics.len(),
            });
        }
        if e.data.len() != data.len() {
            return Err(AbiError::ArityMismatch {
                method: event.to_string(),
                expected: e.data.len(),
                got: data.len(),
            });
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(topics.len() as u32).to_le_bytes());
        for (i, (p, v)) in e.topics.iter().zip(topics.iter()).enumerate() {
            if v.abi_type() != p.ty {
                return Err(AbiError::TypeMismatch {
                    method: event.to_string(),
                    index: i,
                    expected: p.ty,
                    got: v.abi_type(),
                });
            }
            out.push(p.ty.tag());
            out.extend_from_slice(&v.encode_payload()?);
        }
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        for (i, (p, v)) in e.data.iter().zip(data.iter()).enumerate() {
            if v.abi_type() != p.ty {
                return Err(AbiError::TypeMismatch {
                    method: event.to_string(),
                    index: i,
                    expected: p.ty,
                    got: v.abi_type(),
                });
            }
            out.push(p.ty.tag());
            out.extend_from_slice(&v.encode_payload()?);
        }
        Ok(out)
    }

    /// Decode an event payload into `(topics, data)`.
    pub fn decode_event(
        &self,
        event: &str,
        bytes: &[u8],
    ) -> Result<(Vec<AbiValue>, Vec<AbiValue>), AbiError> {
        let e = self
            .event(event)
            .ok_or_else(|| AbiError::UnknownEvent(event.to_string()))?;
        let mut cur = Cursor::new(bytes);
        let topic_count = cur.read_len()?;
        if topic_count != e.topics.len() {
            return Err(AbiError::ArityMismatch {
                method: event.to_string(),
                expected: e.topics.len(),
                got: topic_count,
            });
        }
        let mut topics = Vec::with_capacity(topic_count);
        for (i, p) in e.topics.iter().enumerate() {
            let tag = cur.read_u8()?;
            if tag != p.ty.tag() {
                return Err(AbiError::UnexpectedTypeTag {
                    index: i,
                    expected: p.ty,
                    tag,
                });
            }
            topics.push(AbiValue::decode_payload(p.ty, &mut cur)?);
        }
        let data_count = cur.read_len()?;
        if data_count != e.data.len() {
            return Err(AbiError::ArityMismatch {
                method: event.to_string(),
                expected: e.data.len(),
                got: data_count,
            });
        }
        let mut data = Vec::with_capacity(data_count);
        for (i, p) in e.data.iter().enumerate() {
            let tag = cur.read_u8()?;
            if tag != p.ty.tag() {
                return Err(AbiError::UnexpectedTypeTag {
                    index: i,
                    expected: p.ty,
                    tag,
                });
            }
            data.push(AbiValue::decode_payload(p.ty, &mut cur)?);
        }
        if !cur.is_empty() {
            return Err(AbiError::TrailingBytes {
                got: cur.remaining(),
            });
        }
        Ok((topics, data))
    }

    /// Convert a raw runtime result (`i64` plus optional return data) into the
    /// typed value declared by the manifest.
    ///
    /// Scalars come from the `i64` result; blob returns (`bytes`, `address`,
    /// `string`) come from the contract's return data.
    pub fn decode_runtime_return(
        &self,
        method: &str,
        result: i64,
        return_data: &[u8],
    ) -> Result<AbiValue, AbiError> {
        let m = self
            .method(method)
            .ok_or_else(|| AbiError::UnknownMethod(method.to_string()))?;
        match m.returns {
            AbiType::I64 => Ok(AbiValue::I64(result)),
            AbiType::U64 => Ok(AbiValue::U64(result as u64)),
            AbiType::I32 => Ok(AbiValue::I32(result as i32)),
            AbiType::Bool => Ok(AbiValue::Bool(result != 0)),
            AbiType::Bytes => Ok(AbiValue::Bytes(return_data.to_vec())),
            AbiType::Address => {
                if return_data.len() < ABI_ADDRESS_LEN {
                    return Err(AbiError::BufferTooShort {
                        needed: ABI_ADDRESS_LEN,
                        got: return_data.len(),
                    });
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&return_data[..32]);
                Ok(AbiValue::Address(a))
            }
            AbiType::String => {
                let s = std::str::from_utf8(return_data).map_err(|_| AbiError::InvalidUtf8)?;
                Ok(AbiValue::String(s.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_abi() -> ContractAbi {
        ContractAbi {
            methods: vec![
                AbiMethod::view(
                    "balance_of",
                    vec![AbiParam::new("owner", AbiType::Address)],
                    AbiType::U64,
                ),
                AbiMethod::mutating(
                    "transfer",
                    vec![
                        AbiParam::new("to", AbiType::Address),
                        AbiParam::new("amount", AbiType::U64),
                        AbiParam::new("memo", AbiType::String),
                    ],
                    AbiType::Bool,
                ),
                AbiMethod::view("total", vec![], AbiType::I64),
            ],
            events: vec![AbiEvent::new(
                "Transfer",
                vec![AbiParam::new("from", AbiType::Address)],
                vec![AbiParam::new("amount", AbiType::U64)],
            )],
        }
    }

    fn roundtrip(abi: &ContractAbi, method: &str, args: &[AbiValue]) {
        let enc = abi.encode_args(method, args).unwrap();
        let dec = abi.decode_args(method, &enc).unwrap();
        assert_eq!(dec, args.to_vec(), "round-trip failed for {method}");
    }

    #[test]
    fn every_abi_type_round_trips() {
        let abi = sample_abi();
        let addr = [0x42u8; 32];

        // I64
        let m = AbiMethod::view(
            "f_i64",
            vec![AbiParam::new("v", AbiType::I64)],
            AbiType::I64,
        );
        let mut a = sample_abi();
        a.methods.push(m);
        roundtrip(&a, "f_i64", &[AbiValue::I64(i64::MIN)]);
        roundtrip(&a, "f_i64", &[AbiValue::I64(i64::MAX)]);
        roundtrip(&a, "f_i64", &[AbiValue::I64(-1)]);

        // U64
        let mut a = sample_abi();
        a.methods.push(AbiMethod::view(
            "f_u64",
            vec![AbiParam::new("v", AbiType::U64)],
            AbiType::U64,
        ));
        roundtrip(&a, "f_u64", &[AbiValue::U64(u64::MAX)]);
        roundtrip(&a, "f_u64", &[AbiValue::U64(0)]);

        // I32
        let mut a = sample_abi();
        a.methods.push(AbiMethod::view(
            "f_i32",
            vec![AbiParam::new("v", AbiType::I32)],
            AbiType::I32,
        ));
        roundtrip(&a, "f_i32", &[AbiValue::I32(i32::MIN)]);
        roundtrip(&a, "f_i32", &[AbiValue::I32(i32::MAX)]);

        // Bool
        let mut a = sample_abi();
        a.methods.push(AbiMethod::view(
            "f_bool",
            vec![AbiParam::new("v", AbiType::Bool)],
            AbiType::Bool,
        ));
        roundtrip(&a, "f_bool", &[AbiValue::Bool(true)]);
        roundtrip(&a, "f_bool", &[AbiValue::Bool(false)]);

        // Bytes
        let mut a = sample_abi();
        a.methods.push(AbiMethod::view(
            "f_bytes",
            vec![AbiParam::new("v", AbiType::Bytes)],
            AbiType::Bytes,
        ));
        roundtrip(&a, "f_bytes", &[AbiValue::Bytes(vec![])]);
        roundtrip(&a, "f_bytes", &[AbiValue::Bytes(vec![0, 1, 2, 255])]);

        // Address
        roundtrip(&abi, "balance_of", &[AbiValue::Address(addr)]);

        // String
        roundtrip(
            &abi,
            "transfer",
            &[
                AbiValue::Address(addr),
                AbiValue::U64(7),
                AbiValue::String("hello".into()),
            ],
        );
        roundtrip(
            &abi,
            "transfer",
            &[
                AbiValue::Address(addr),
                AbiValue::U64(0),
                AbiValue::String(String::new()),
            ],
        );
    }

    #[test]
    fn multi_arg_method_round_trips_and_is_order_stable() {
        let abi = sample_abi();
        let a1 = [1u8; 32];
        let a2 = [2u8; 32];
        let args = vec![
            AbiValue::Address(a1),
            AbiValue::U64(1234),
            AbiValue::String("memo".into()),
        ];
        let enc = abi.encode_args("transfer", &args).unwrap();
        let dec = abi.decode_args("transfer", &enc).unwrap();
        assert_eq!(dec, args);

        // The parameter order is part of the encoding: two calls with the
        // same values in a different order produce different bytes.
        let mut abi2 = sample_abi();
        abi2.methods.push(AbiMethod::view(
            "add2",
            vec![
                AbiParam::new("a", AbiType::I64),
                AbiParam::new("b", AbiType::I64),
            ],
            AbiType::I64,
        ));
        let enc1 = abi2
            .encode_args("add2", &[AbiValue::I64(1), AbiValue::I64(2)])
            .unwrap();
        let enc2 = abi2
            .encode_args("add2", &[AbiValue::I64(2), AbiValue::I64(1)])
            .unwrap();
        assert_ne!(enc1, enc2, "argument order must be part of the encoding");
        assert_eq!(
            abi2.decode_args("add2", &enc1).unwrap(),
            vec![AbiValue::I64(1), AbiValue::I64(2)]
        );
        assert_eq!(
            abi2.decode_args("add2", &enc2).unwrap(),
            vec![AbiValue::I64(2), AbiValue::I64(1)]
        );
        let _ = (a2,);
    }

    #[test]
    fn encoding_is_length_prefixed_and_tagged() {
        let abi = sample_abi();
        let enc = abi
            .encode_args(
                "transfer",
                &[
                    AbiValue::Address([0u8; 32]),
                    AbiValue::U64(1),
                    AbiValue::String("ab".into()),
                ],
            )
            .unwrap();
        // u32_le(arg_count) = 3
        assert_eq!(&enc[0..4], &3u32.to_le_bytes());
        // first arg: ADDRESS tag + 32 bytes
        assert_eq!(enc[4], ABI_TAG_ADDRESS);
        // second arg: U64 tag + 8 bytes big-endian
        assert_eq!(enc[37], ABI_TAG_U64);
        assert_eq!(&enc[38..46], &1u64.to_be_bytes());
        // third arg: STRING tag + u32_le(len) + payload
        assert_eq!(enc[46], ABI_TAG_STRING);
        assert_eq!(&enc[47..51], &2u32.to_le_bytes());
        assert_eq!(&enc[51..53], b"ab");
        assert_eq!(enc.len(), 53);
    }

    #[test]
    fn zero_arg_method_round_trips() {
        let abi = sample_abi();
        let enc = abi.encode_args("total", &[]).unwrap();
        assert_eq!(enc, 0u32.to_le_bytes().to_vec());
        assert!(abi.decode_args("total", &enc).unwrap().is_empty());
    }

    #[test]
    fn json_manifest_round_trips() {
        let abi = sample_abi();
        let json = abi.to_json();
        let back = ContractAbi::from_json(&json).unwrap();
        assert_eq!(abi, back);

        let pretty = abi.to_json_pretty();
        let back = ContractAbi::from_json(pretty).unwrap();
        assert_eq!(abi, back);

        let value = abi.to_json_value();
        let back = ContractAbi::from_json_value(&value).unwrap();
        assert_eq!(abi, back);
    }

    #[test]
    fn json_manifest_is_stable_and_readable() {
        let abi = sample_abi();
        let json = abi.to_json();
        assert!(json.contains("\"methods\""));
        assert!(json.contains("\"events\""));
        assert!(json.contains("\"mutates_state\""));
        assert!(json.contains("\"type\":\"address\""));
        assert!(json.contains("\"returns\":\"bool\""));
    }

    #[test]
    fn json_manifest_accepts_near_style_aliases() {
        let raw = r#"{
            "methods": [
                {"name": "ft_transfer", "params": [{"name": "receiver_id", "type": "AccountId"}],
                 "returns": "U64", "mutates_state": true}
            ],
            "events": []
        }"#;
        let abi = ContractAbi::from_json(raw).unwrap();
        assert_eq!(abi.methods.len(), 1);
        assert_eq!(abi.methods[0].params[0].ty, AbiType::Address);
        assert_eq!(abi.methods[0].returns, AbiType::U64);
        assert!(abi.methods[0].mutates_state);
    }

    #[test]
    fn unknown_method_and_arity_are_rejected() {
        let abi = sample_abi();
        assert!(matches!(
            abi.encode_args("nope", &[]),
            Err(AbiError::UnknownMethod(_))
        ));
        assert!(matches!(
            abi.encode_args("total", &[AbiValue::I64(1)]),
            Err(AbiError::ArityMismatch { .. })
        ));
        assert!(matches!(
            abi.encode_args("balance_of", &[AbiValue::U64(1)]),
            Err(AbiError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn decode_rejects_truncated_and_trailing_bytes() {
        let abi = sample_abi();
        let enc = abi
            .encode_args("balance_of", &[AbiValue::Address([3u8; 32])])
            .unwrap();
        assert!(matches!(
            abi.decode_args("balance_of", &enc[..10]),
            Err(AbiError::BufferTooShort { .. })
        ));
        let mut extra = enc.clone();
        extra.push(0);
        assert!(matches!(
            abi.decode_args("balance_of", &extra),
            Err(AbiError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn return_values_round_trip() {
        let abi = sample_abi();
        for (method, value) in [
            ("balance_of", AbiValue::U64(99)),
            ("transfer", AbiValue::Bool(true)),
            ("total", AbiValue::I64(-7)),
        ] {
            let enc = abi.encode_return(method, &value).unwrap();
            assert_eq!(abi.decode_return(method, &enc).unwrap(), value);
        }
        // A bare (untagged) payload is accepted as well.
        assert_eq!(
            abi.decode_return("total", &(-7i64).to_be_bytes()).unwrap(),
            AbiValue::I64(-7)
        );
    }

    #[test]
    fn call_payload_round_trips() {
        let abi = sample_abi();
        let args = vec![AbiValue::Address([9u8; 32])];
        let call = abi.encode_call("balance_of", &args).unwrap();
        assert_eq!(&call[0..4], &ContractAbi::method_selector("balance_of"));
        let (method, decoded) = abi.decode_call(&call).unwrap();
        assert_eq!(method, "balance_of");
        assert_eq!(decoded, args);
    }

    #[test]
    fn event_payload_round_trips() {
        let abi = sample_abi();
        let enc = abi
            .encode_event(
                "Transfer",
                &[AbiValue::Address([4u8; 32])],
                &[AbiValue::U64(77)],
            )
            .unwrap();
        let (topics, data) = abi.decode_event("Transfer", &enc).unwrap();
        assert_eq!(topics, vec![AbiValue::Address([4u8; 32])]);
        assert_eq!(data, vec![AbiValue::U64(77)]);
    }

    #[test]
    fn type_tags_are_stable_and_unique() {
        let mut seen = Vec::new();
        for t in AbiType::ALL {
            assert_eq!(AbiType::from_tag(t.tag()), Some(t));
            assert!(!seen.contains(&t.tag()), "duplicate type tag");
            seen.push(t.tag());
            assert_eq!(AbiType::parse(t.as_str()), Some(t));
        }
        assert_eq!(seen, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn values_convert_to_json_and_back() {
        let addr = [0x11u8; 32];
        // Blobs, addresses, strings and booleans keep their type through JSON.
        for v in [
            AbiValue::Bool(true),
            AbiValue::Bytes(vec![1, 2, 3]),
            AbiValue::Address(addr),
            AbiValue::String("hi".into()),
        ] {
            let json = v.to_json_value();
            let back = AbiValue::from_json_value(&json).unwrap();
            assert_eq!(back, v);
        }
        // A JSON number carries no signedness, so only the value survives.
        for v in [AbiValue::I64(-5), AbiValue::U64(5), AbiValue::I32(-3)] {
            let json = v.to_json_value();
            let back = AbiValue::from_json_value(&json).unwrap();
            assert_eq!(back.as_i64(), v.as_i64());
        }
    }

    #[test]
    fn runtime_return_is_typed() {
        let abi = sample_abi();
        assert_eq!(
            abi.decode_runtime_return("total", 42, &[]).unwrap(),
            AbiValue::I64(42)
        );
        assert_eq!(
            abi.decode_runtime_return("balance_of", 5, &[]).unwrap(),
            AbiValue::U64(5)
        );
        assert_eq!(
            abi.decode_runtime_return("transfer", 1, &[]).unwrap(),
            AbiValue::Bool(true)
        );
        assert_eq!(
            abi.decode_runtime_return("total", 0, b"abc").unwrap(),
            AbiValue::I64(0)
        );
    }

    #[test]
    fn coercion_is_lossless_only() {
        assert_eq!(
            AbiValue::I64(5).coerce_to(AbiType::U64).unwrap(),
            AbiValue::U64(5)
        );
        assert!(AbiValue::I64(-1).coerce_to(AbiType::U64).is_err());
        assert_eq!(
            AbiValue::Bool(true).coerce_to(AbiType::I64).unwrap(),
            AbiValue::I64(1)
        );
    }
}
