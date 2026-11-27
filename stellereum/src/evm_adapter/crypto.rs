use super::*;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// secp256k1 curve order N (for low-s normalization of settlement signatures).
pub const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

// Ethereum Cryptography: secp256k1 ECDSA, Keccak-256 & ecrecover
// ============================================================================

/// secp256k1 curve order N / 2, the threshold for low-s values (EIP-2 malleability protection).
/// N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// N / 2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
pub const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Errors occurring during Ethereum signature verification or address recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmError {
    InvalidRecoveryId(u64),
    InvalidSignatureR,
    InvalidSignatureS,
    InvalidSignature(String),
    InvalidPublicKey(String),
    InvalidMessageHash(String),
    ChainIdMismatch { expected: u64, got: u64 },
    ReplayProtectionRequired,
    HexDecodeError(String),
    InvalidAddressLength(usize),
    SignatureRecoveryFailed(String),
}

impl std::fmt::Display for EvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecoveryId(v) => write!(f, "invalid recovery id / v parameter: {v}"),
            Self::InvalidSignatureR => write!(
                f,
                "signature r value must be non-zero and within curve order"
            ),
            Self::InvalidSignatureS => write!(
                f,
                "signature s value must be non-zero and within allowed range"
            ),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::InvalidPublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::InvalidMessageHash(e) => write!(f, "invalid message hash: {e}"),
            Self::ChainIdMismatch { expected, got } => {
                write!(
                    f,
                    "EIP-155 chain ID mismatch: expected {expected}, got {got}"
                )
            }
            Self::ReplayProtectionRequired => {
                write!(
                    f,
                    "EIP-155 replay protection required, but legacy unprotected signature received"
                )
            }
            Self::HexDecodeError(e) => write!(f, "hex decoding failed: {e}"),
            Self::InvalidAddressLength(len) => {
                write!(f, "invalid address length: expected 20 bytes, got {len}")
            }
            Self::SignatureRecoveryFailed(e) => write!(f, "ECDSA public key recovery failed: {e}"),
        }
    }
}

impl std::error::Error for EvmError {}

/// Derives the 20-byte Ethereum address from a secp256k1 public key.
///
/// Formula: `keccak256(pubkey_uncompressed[1..])[12..32]`.
///
/// Accepts:
/// - 65-byte uncompressed public key (starts with 0x04)
/// - 64-byte raw uncompressed public key coordinates (X || Y)
/// - 33-byte compressed public key (starts with 0x02 or 0x03)
pub fn pubkey_to_address(pubkey: &[u8]) -> Result<[u8; 20], EvmError> {
    let uncompressed_raw = if pubkey.len() == 65 && pubkey[0] == 0x04 {
        &pubkey[1..65]
    } else if pubkey.len() == 64 {
        pubkey
    } else if pubkey.len() == 33 {
        let vk = VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|e| EvmError::InvalidPublicKey(e.to_string()))?;
        let encoded = vk.to_encoded_point(false);
        let uncompressed = encoded.as_bytes();
        let hash = keccak256(&uncompressed[1..65]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        return Ok(addr);
    } else {
        return Err(EvmError::InvalidPublicKey(format!(
            "expected 65-byte uncompressed, 64-byte raw, or 33-byte compressed public key, got {} bytes",
            pubkey.len()
        )));
    };

    let hash = keccak256(uncompressed_raw);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

/// Returns true if signature scalar `s` is in the lower half of the curve order
/// (`s <= secp256k1_n / 2`), protecting against malleability under EIP-2.
pub fn is_low_s(s: &[u8; 32]) -> bool {
    s <= &SECP256K1_HALF_N
}

/// Decomposes an Ethereum `v` value into `(recovery_id, Option<chain_id>)`.
///
/// Supports:
/// - EIP-1559 / typed transactions (EIP-2718): `v = 0` or `1` (y_parity) -> recovery_id = 0/1, chain_id = None.
/// - Pre-EIP-155 legacy transactions: `v = 27` or `28` -> recovery_id = v - 27, chain_id = None.
/// - EIP-155 replay protected transactions: `v >= 35` (where `v = chain_id * 2 + 35 + recovery_id`) ->
///   recovery_id = (v - 35) % 2, chain_id = Some((v - 35) / 2).
pub fn parse_v(v: u64) -> Result<(u8, Option<u64>), EvmError> {
    if v == 0 || v == 1 {
        Ok((v as u8, None))
    } else if v == 27 || v == 28 {
        Ok(((v - 27) as u8, None))
    } else if v >= 35 {
        let chain_id = (v - 35) / 2;
        let rec_id = ((v - 35 - 2 * chain_id) % 2) as u8;
        Ok((rec_id, Some(chain_id)))
    } else {
        Err(EvmError::InvalidRecoveryId(v))
    }
}

/// Decomposes `v` and verifies EIP-155 chain ID replay protection against `expected_chain_id`.
///
/// If `expected_chain_id` is `Some(id)`:
/// - If `v >= 35`, requires derived `chain_id == id`.
/// - If `v == 0` or `1` (EIP-1559), accepted as chain ID is validated via the transaction envelope.
/// - If `v == 27` or `28`, returns `EvmError::ReplayProtectionRequired` (unprotected legacy transaction).
pub fn parse_v_with_chain_id(
    v: u64,
    expected_chain_id: Option<u64>,
) -> Result<(u8, Option<u64>), EvmError> {
    parse_v_with_chain_id_opts(v, expected_chain_id, false)
}

/// Decomposes `v` with optional allowance for unprotected pre-EIP-155 legacy transactions (v = 27, 28).
pub fn parse_v_with_chain_id_opts(
    v: u64,
    expected_chain_id: Option<u64>,
    allow_unprotected: bool,
) -> Result<(u8, Option<u64>), EvmError> {
    let (rec_id, chain_id) = parse_v(v)?;
    if let Some(expected) = expected_chain_id {
        match chain_id {
            Some(got) => {
                if got != expected {
                    return Err(EvmError::ChainIdMismatch { expected, got });
                }
            }
            None => {
                if (v == 27 || v == 28) && !allow_unprotected {
                    return Err(EvmError::ReplayProtectionRequired);
                }
            }
        }
    }
    Ok((rec_id, chain_id))
}

/// Given an Ethereum 32-byte message hash `hash` and signature `(v, r, s)`, recovers the 20-byte sender address.
///
/// Supports:
/// - EIP-155 replay-protected transactions (`v = 2 * chain_id + 35 + rec_id` -> extraction `rec_id = (v - 35 - 2 * chain_id) % 2`)
/// - EIP-1559 typed transactions (`v = 0` or `1`)
/// - Pre-EIP-155 legacy transactions (`v = 27` or `28` -> `rec_id = v - 27`)
///
/// Computes the 20-byte sender address: `keccak256(&uncompressed_pubkey[1..])[12..32]`.
pub fn ecrecover(hash: &[u8; 32], v: u64, r: &[u8; 32], s: &[u8; 32]) -> Result<[u8; 20], String> {
    ecrecover_with_chain_id(hash, v, r, s, None).map_err(|e| e.to_string())
}

/// Validates an Ethereum transaction signature:
/// - Replay protection: verifies `chain_id == effective_chain_id()`.
/// - Canonical s: verifies `s <= secp256k1_order / 2` (EIP-2).
///   Recovers and returns the 20-byte sender address.
pub fn validate_transaction_signature(
    hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 20], String> {
    validate_transaction_signature_with_chain_id(hash, v, r, s, Some(effective_chain_id()))
}

/// Validates an Ethereum transaction signature against an expected chain ID:
/// - Replay protection: verifies that the signature's chain ID matches `expected_chain_id`.
/// - Canonical s: verifies `s <= secp256k1_order / 2` (EIP-2).
///   Recovers and returns the 20-byte sender address.
pub fn validate_transaction_signature_with_chain_id(
    hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 20], String> {
    // 1. EIP-2 canonical low-s check: s <= secp256k1_order / 2
    if !is_low_s(s) {
        return Err(
            "signature s is not canonical: must be <= secp256k1_order / 2 (EIP-2)".to_string(),
        );
    }

    // 2. Replay protection check: chain_id == expected_chain_id
    if let Some(expected) = expected_chain_id {
        if v >= 35 {
            let chain_id = (v - 35) / 2;
            if chain_id != expected {
                return Err(format!(
                    "EIP-155 replay protection mismatch: expected chain_id {}, got {}",
                    expected, chain_id
                ));
            }
        } else if v == 27 || v == 28 {
            return Err("EIP-155 replay protection required, but legacy unprotected signature received (v = 27/28)".to_string());
        } else if v == 0 || v == 1 {
            // EIP-1559 typed transaction (y_parity)
        } else {
            return Err(format!("invalid recovery id / v parameter: {v}"));
        }
    }

    ecrecover(hash, v, r, s)
}

/// Convenience alias for `validate_transaction_signature`.
pub fn verify_transaction_signature(
    hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 20], String> {
    validate_transaction_signature(hash, v, r, s)
}

/// Given an Ethereum 32-byte message hash `e` and signature `(v, r, s)`, recovers the 20-byte sender address
/// and verifies EIP-155 chain ID replay protection against `expected_chain_id`.
pub fn ecrecover_with_chain_id(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 20], EvmError> {
    let pubkey_bytes = ecrecover_pubkey_with_chain_id(message_hash, v, r, s, expected_chain_id)?;
    pubkey_to_address(&pubkey_bytes)
}

/// Recovers the uncompressed 65-byte public key (starts with 0x04) from message hash and signature (v, r, s).
pub fn ecrecover_pubkey(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 65], EvmError> {
    ecrecover_pubkey_with_chain_id(message_hash, v, r, s, None)
}

/// Recovers the uncompressed 65-byte public key with EIP-155 chain ID verification.
pub fn ecrecover_pubkey_with_chain_id(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 65], EvmError> {
    let (rec_id, _) = parse_v_with_chain_id(v, expected_chain_id)?;

    if r == &[0u8; 32] {
        return Err(EvmError::InvalidSignatureR);
    }
    if s == &[0u8; 32] {
        return Err(EvmError::InvalidSignatureS);
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| EvmError::InvalidSignature(e.to_string()))?;

    let recid = RecoveryId::try_from(rec_id).map_err(|_| EvmError::InvalidRecoveryId(v))?;

    let vk = VerifyingKey::recover_from_prehash(message_hash, &signature, recid)
        .map_err(|e| EvmError::SignatureRecoveryFailed(e.to_string()))?;

    let encoded = vk.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Recovers the sender address and strictly validates `s <= secp256k1_n / 2` (EIP-2 malleability protection).
pub fn ecrecover_tx(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 20], EvmError> {
    if !is_low_s(s) {
        return Err(EvmError::InvalidSignatureS);
    }
    ecrecover_with_chain_id(message_hash, v, r, s, expected_chain_id)
}

/// Verifies that an Ethereum signature `(v, r, s)` over `message_hash` was produced by `expected_address`.
pub fn verify_signature(
    expected_address: &[u8; 20],
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<bool, EvmError> {
    let recovered = ecrecover(message_hash, v, r, s).map_err(EvmError::SignatureRecoveryFailed)?;
    Ok(recovered == *expected_address)
}

/// Verifies that an Ethereum signature `(v, r, s)` over `message_hash` was produced by `expected_address`
/// with EIP-155 chain ID replay protection.
pub fn verify_signature_with_chain_id(
    expected_address: &[u8; 20],
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<bool, EvmError> {
    let recovered = ecrecover_with_chain_id(message_hash, v, r, s, expected_chain_id)?;
    Ok(recovered == *expected_address)
}

/// Hex string convenience method for `ecrecover`. Returns formatted "0x..." checksum address.
pub fn ecrecover_hex(
    message_hash_hex: &str,
    v_hex: &str,
    r_hex: &str,
    s_hex: &str,
) -> Result<String, EvmError> {
    ecrecover_hex_with_chain_id(message_hash_hex, v_hex, r_hex, s_hex, None)
}

/// Hex string convenience method for `ecrecover` with EIP-155 chain ID check.
pub fn ecrecover_hex_with_chain_id(
    message_hash_hex: &str,
    v_hex: &str,
    r_hex: &str,
    s_hex: &str,
    expected_chain_id: Option<u64>,
) -> Result<String, EvmError> {
    let hash = parse_h256(message_hash_hex)?;
    let v = parse_v_str(v_hex)?;
    let r = parse_h256(r_hex)?;
    let s = parse_h256(s_hex)?;
    let addr = ecrecover_with_chain_id(&hash, v, &r, &s, expected_chain_id)?;
    Ok(to_checksum_address(&addr))
}

/// Formats a 20-byte address into an EIP-55 mixed-case checksummed hex string ("0x...").
pub fn to_checksum_address(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let hash = keccak256(hex_addr.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_alphabetic() {
            let byte_idx = i / 2;
            let nibble = if i % 2 == 0 {
                (hash[byte_idx] >> 4) & 0x0f
            } else {
                hash[byte_idx] & 0x0f
            };
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c.to_ascii_lowercase());
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses a 20-byte Ethereum address from a hex string (with or without 0x prefix).
pub fn parse_address(s: &str) -> Result<[u8; 20], EvmError> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
        .map_err(|e| EvmError::HexDecodeError(format!("invalid hex in address '{s}': {e}")))?;
    if bytes.len() != 20 {
        return Err(EvmError::InvalidAddressLength(bytes.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parses a 32-byte hash / scalar from a hex string (with or without 0x prefix).
pub fn parse_h256(s: &str) -> Result<[u8; 32], EvmError> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
        .map_err(|e| EvmError::HexDecodeError(format!("invalid hex in '{s}': {e}")))?;
    if bytes.len() > 32 {
        return Err(EvmError::InvalidMessageHash(format!(
            "hex string too long for 32 bytes: {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Parses `v` value from a string (handles "0x" hex quantities and decimal integers).
pub fn parse_v_str(s: &str) -> Result<u64, EvmError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(EvmError::HexDecodeError("empty v string".to_string()));
    }
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        let hex_part = &trimmed[2..];
        if hex_part.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(hex_part, 16)
            .map_err(|e| EvmError::HexDecodeError(format!("invalid hex v '{s}': {e}")))
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|e| EvmError::HexDecodeError(format!("invalid integer v '{s}': {e}")))
    }
}

/// Computes the signing hash for a pre-EIP-155 legacy transaction:
/// `keccak256(RLP([nonce, gas_price, gas_limit, to, value, data]))`.
pub fn legacy_tx_signing_hash(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<&[u8; 20]>,
    value: u128,
    data: &[u8],
) -> [u8; 32] {
    let to_enc = match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    };
    let items = vec![
        rlp::encode_u64(nonce),
        rlp::encode_u128(gas_price),
        rlp::encode_u64(gas_limit),
        to_enc,
        rlp::encode_u128(value),
        rlp::encode_bytes(data),
    ];
    let payload = rlp::encode_list(&items);
    keccak256(&payload)
}

/// Computes the signing hash for an EIP-155 replay-protected transaction:
/// `keccak256(RLP([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]))`.
pub fn eip155_tx_signing_hash(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<&[u8; 20]>,
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> [u8; 32] {
    let to_enc = match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    };
    let items = vec![
        rlp::encode_u64(nonce),
        rlp::encode_u128(gas_price),
        rlp::encode_u64(gas_limit),
        to_enc,
        rlp::encode_u128(value),
        rlp::encode_bytes(data),
        rlp::encode_u64(chain_id),
        rlp::encode_u64(0),
        rlp::encode_u64(0),
    ];
    let payload = rlp::encode_list(&items);
    keccak256(&payload)
}

/// Computes the signing hash for an EIP-1559 typed transaction (Type 0x02):
/// `keccak256(0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list]))`.
///
/// Rejects malformed hex / wrong-length access list entries with `invalid_params`
/// instead of silently zero-filling.
#[allow(clippy::too_many_arguments)]
// GATE: EIP-1559 signing hash takes the full tx field set per spec; grouping would diverge from the yellow-paper layout.
pub fn eip1559_tx_signing_hash(
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Option<&[u8; 20]>,
    value: u128,
    data: &[u8],
    access_list: &[EvmAccessListItem],
) -> Result<[u8; 32], JsonRpcError> {
    let to_enc = match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    };

    let mut access_list_items = Vec::with_capacity(access_list.len());
    for item in access_list {
        let addr_bytes = parse_address(&item.address).map_err(|e| {
            JsonRpcError::invalid_params(format!(
                "invalid accessList address '{}': {e}",
                item.address
            ))
        })?;
        let mut keys = Vec::with_capacity(item.storage_keys.len());
        for k in &item.storage_keys {
            let k_bytes = parse_h256(k).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid accessList storage key '{k}': {e}"))
            })?;
            keys.push(rlp::encode_bytes(&k_bytes));
        }
        access_list_items.push(rlp::encode_list(&[
            rlp::encode_bytes(&addr_bytes),
            rlp::encode_list(&keys),
        ]));
    }

    let items = vec![
        rlp::encode_u64(chain_id),
        rlp::encode_u64(nonce),
        rlp::encode_u128(max_priority_fee_per_gas),
        rlp::encode_u128(max_fee_per_gas),
        rlp::encode_u64(gas_limit),
        to_enc,
        rlp::encode_u128(value),
        rlp::encode_bytes(data),
        rlp::encode_list(&access_list_items),
    ];

    let rlp_payload = rlp::encode_list(&items);
    let mut message = Vec::with_capacity(1 + rlp_payload.len());
    message.push(0x02);
    message.extend_from_slice(&rlp_payload);
    Ok(keccak256(&message))
}

#[cfg(test)]
mod eip1559_signing_hash_tests {
    use super::*;

    #[test]
    fn rejects_invalid_access_list_hex() {
        let bad_addr = [EvmAccessListItem {
            address: "0xnot_hex".to_string(),
            storage_keys: vec![],
        }];
        let err = eip1559_tx_signing_hash(CHAIN_ID, 0, 1, 2, 21_000, None, 0, &[], &bad_addr)
            .expect_err("invalid access list address must error");
        assert_eq!(err.code, INVALID_PARAMS_CODE);

        let bad_key = [EvmAccessListItem {
            address: format!("0x{}", "11".repeat(20)),
            storage_keys: vec!["0xzzzz".to_string()],
        }];
        let err = eip1559_tx_signing_hash(CHAIN_ID, 0, 1, 2, 21_000, None, 0, &[], &bad_key)
            .expect_err("invalid access list storage key must error");
        assert_eq!(err.code, INVALID_PARAMS_CODE);

        let valid = [EvmAccessListItem {
            address: format!("0x{}", "11".repeat(20)),
            storage_keys: vec![format!("0x{}", "aa".repeat(32))],
        }];
        assert!(eip1559_tx_signing_hash(CHAIN_ID, 0, 1, 2, 21_000, None, 0, &[], &valid).is_ok());
    }
}
