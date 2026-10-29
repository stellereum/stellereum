//! Stellereum Branded Address Format (`Stl57...`)
//!
//! Features:
//! - Human-readable branded prefix: `Stl57` (representing Stellereum L1 & Chain ID 5757).
//! - Base58 encoding (zero ambiguity: no 0/O/I/l).
//! - 4-byte BLAKE3 cryptographic checksum protecting against accidental typos.
//! - Strict ASCII validation preventing Unicode homoglyph injection.
//! - Transparent bidirectional conversion between raw `[u8; 32]`, 64-character hex, and `Stl57`.

use blake3::Hasher;

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PREFIX: &str = "Stl57";
const CHECKSUM_DOMAIN: &str = "STELLEREUM_ADDRESS_CHECKSUM_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    InvalidPrefix,
    InvalidLength,
    InvalidBase58,
    InvalidChecksum,
    InvalidHex,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressError::Empty => write!(f, "address is empty"),
            AddressError::InvalidPrefix => write!(f, "invalid address prefix, expected 'Stl57' or '0x'"),
            AddressError::InvalidLength => write!(f, "invalid address length"),
            AddressError::InvalidBase58 => write!(f, "invalid base58 character in address"),
            AddressError::InvalidChecksum => write!(f, "address checksum mismatch (typo detected)"),
            AddressError::InvalidHex => write!(f, "invalid hex address"),
        }
    }
}

impl std::error::Error for AddressError {}

/// Calculate 4-byte BLAKE3 checksum for raw 32-byte address.
fn calculate_checksum(addr: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Hasher::new_derive_key(CHECKSUM_DOMAIN);
    hasher.update(addr);
    let hash = hasher.finalize();
    let mut check = [0u8; 4];
    check.copy_from_slice(&hash.as_bytes()[..4]);
    check
}

/// Encode raw 32-byte address into branded `Stl57...` format with 4-byte checksum.
pub fn encode_stl57_address(addr: &[u8; 32]) -> String {
    let checksum = calculate_checksum(addr);
    let mut payload = [0u8; 36];
    payload[..32].copy_from_slice(addr);
    payload[32..].copy_from_slice(&checksum);

    let b58 = base58_encode(&payload);
    format!("{PREFIX}{b58}")
}

/// Parse any supported address string:
/// - Branded `Stl57...` or `stl57...` (Base58 with checksum).
/// - Bare hex or `0x`-prefixed 64-hex characters.
pub fn parse_address(input: &str) -> Result<[u8; 32], AddressError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(AddressError::Empty);
    }

    // Check for Stl57 prefix (case-insensitive on the 5 prefix characters, safe against UTF-8 multi-byte boundaries)
    if s.get(..5).map_or(false, |prefix| prefix.eq_ignore_ascii_case("stl57")) {
        let b58_part = &s[5..];
        // Length pre-check to prevent quadratic big-int CPU exhaustion
        if b58_part.len() < 35 || b58_part.len() > 51 {
            return Err(AddressError::InvalidLength);
        }

        let bytes = base58_decode(b58_part)?;
        if bytes.len() != 36 {
            return Err(AddressError::InvalidLength);
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes[..32]);

        let mut expected_check = [0u8; 4];
        expected_check.copy_from_slice(&bytes[32..]);
        let calculated = calculate_checksum(&addr);

        if expected_check != calculated {
            return Err(AddressError::InvalidChecksum);
        }
        return Ok(addr);
    }

    // Fallback: 64-character hex (with optional 0x/0X prefix)
    let hex_part = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if hex_part.len() == 64 {
        let decoded = hex::decode(hex_part).map_err(|_| AddressError::InvalidHex)?;
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&decoded);
        return Ok(addr);
    }

    // Discriminate length vs prefix errors
    if s.starts_with("0x") || s.starts_with("0X") || s.len() == 64 {
        Err(AddressError::InvalidLength)
    } else {
        Err(AddressError::InvalidPrefix)
    }
}

/// Pure Rust Base58 encoder (no external crate dependency).
pub fn base58_encode(input: &[u8]) -> String {
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &b in input.iter().skip(leading_zeros) {
        let mut carry = b as usize;
        for digit in digits.iter_mut() {
            carry += (*digit as usize) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut result = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        result.push('1');
    }
    for &digit in digits.iter().rev() {
        result.push(BASE58_ALPHABET[digit as usize] as char);
    }
    result
}

/// Pure Rust Base58 decoder with strict ASCII validation.
pub fn base58_decode(input: &str) -> Result<Vec<u8>, AddressError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut bytes: Vec<u8> = Vec::new();
    for c in input.chars() {
        // Enforce strict ASCII to eliminate Unicode homoglyph code point truncation
        if !c.is_ascii() {
            return Err(AddressError::InvalidBase58);
        }
        let ascii_byte = c as u8;
        let val = BASE58_ALPHABET
            .iter()
            .position(|&b| b == ascii_byte)
            .ok_or(AddressError::InvalidBase58)?;

        let mut carry = val;
        for byte in bytes.iter_mut() {
            carry += (*byte as usize) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Leading zeros ('1' in Base58 represents a leading 0x00 byte)
    let leading_zeros = input.chars().take_while(|&c| c == '1').count();
    let mut result = vec![0u8; leading_zeros];
    result.extend(bytes.into_iter().rev());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_parse_stl57_roundtrip() {
        let original_addr = [0xABu8; 32];
        let encoded = encode_stl57_address(&original_addr);
        assert!(encoded.starts_with("Stl57"));
        println!("Sample Stl57 address: {encoded}");

        let parsed = parse_address(&encoded).expect("parse must succeed");
        assert_eq!(parsed, original_addr);

        // Lowercase prefix 'stl57' must also parse
        let lower_prefix = format!("stl57{}", &encoded[5..]);
        let parsed_lower = parse_address(&lower_prefix).expect("lowercase prefix must parse");
        assert_eq!(parsed_lower, original_addr);

        // Uppercase prefix 'STL57' must also parse
        let upper_prefix = format!("STL57{}", &encoded[5..]);
        let parsed_upper = parse_address(&upper_prefix).expect("uppercase prefix must parse");
        assert_eq!(parsed_upper, original_addr);
    }

    #[test]
    fn test_typo_checksum_rejection() {
        let addr = [0x77u8; 32];
        let mut encoded = encode_stl57_address(&addr);
        let last_char = encoded.pop().unwrap();
        let replacement = if last_char == '9' { '8' } else { '9' };
        encoded.push(replacement);

        let err = parse_address(&encoded);
        assert_eq!(err, Err(AddressError::InvalidChecksum));
    }

    #[test]
    fn test_unicode_homoglyphs_rejected() {
        // Cyrillic Small Letter Es ('\u{0441}') which truncates to ASCII 'A'
        let fake = "Stl572Jc6VooH5wxteNEnVgqR8hNw3Pb58bphqk1myKZpXwrCfg7sR\u{0441}";
        let res = parse_address(fake);
        assert_eq!(res, Err(AddressError::InvalidBase58));
    }

    #[test]
    fn test_hex_compatibility() {
        let addr = [0x42u8; 32];
        let hex_str = format!("0x{}", hex::encode(addr));
        let parsed = parse_address(&hex_str).expect("hex must parse");
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_burn_address_encoding() {
        let burn_addr = [0u8; 32];
        let encoded = encode_stl57_address(&burn_addr);
        println!("Official Burn Address in Stl57: {encoded}");
        let parsed = parse_address(&encoded).unwrap();
        assert_eq!(parsed, [0u8; 32]);
    }
}
