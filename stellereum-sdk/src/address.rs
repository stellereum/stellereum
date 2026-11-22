//! 32-byte addresses, hex and the branded `Stl57...` format.
//!
//! This mirrors `stellereum/src/address.rs` byte-for-byte:
//! `Stl57` + base58(`address(32) || BLAKE3("STELLEREUM_ADDRESS_CHECKSUM_V1",
//! address)[..4]`). It is reimplemented here (not imported) so a client
//! binary does not link the node crate; `tests/parity.rs` pins the output to
//! the node's `encode_stl57_address` / `parse_address`.

use crate::error::{Result, SdkError};

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PREFIX: &str = "Stl57";
const CHECKSUM_DOMAIN: &str = "STELLEREUM_ADDRESS_CHECKSUM_V1";

fn checksum(addr: &[u8; 32]) -> [u8; 4] {
    let mut h = blake3::Hasher::new_derive_key(CHECKSUM_DOMAIN);
    h.update(addr);
    let out = h.finalize();
    let mut c = [0u8; 4];
    c.copy_from_slice(&out.as_bytes()[..4]);
    c
}

/// Encode a raw 32-byte address as `Stl57...`.
pub fn encode_stl57(addr: &[u8; 32]) -> String {
    let mut payload = [0u8; 36];
    payload[..32].copy_from_slice(addr);
    payload[32..].copy_from_slice(&checksum(addr));
    format!("{PREFIX}{}", base58_encode(&payload))
}

/// Parse `Stl57...` (case-insensitive prefix), bare 64-char hex, or
/// `0x`-prefixed 64-char hex.
pub fn parse_address(input: &str) -> Result<[u8; 32]> {
    let s = input.trim();
    if s.is_empty() {
        return Err(SdkError::InvalidAddress("address is empty".into()));
    }
    if s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case(PREFIX)) {
        let body = &s[5..];
        if !(35..=51).contains(&body.len()) {
            return Err(SdkError::InvalidAddress("invalid Stl57 length".into()));
        }
        let bytes = base58_decode(body)
            .map_err(|e| SdkError::InvalidAddress(format!("invalid base58: {e}")))?;
        if bytes.len() != 36 {
            return Err(SdkError::InvalidAddress(
                "invalid Stl57 payload length".into(),
            ));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes[..32]);
        let mut expected = [0u8; 4];
        expected.copy_from_slice(&bytes[32..]);
        if checksum(&addr) != expected {
            return Err(SdkError::InvalidAddress(
                "address checksum mismatch (typo detected)".into(),
            ));
        }
        return Ok(addr);
    }
    let hex_part = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if hex_part.len() == 64 {
        let bytes =
            hex::decode(hex_part).map_err(|_| SdkError::InvalidAddress("invalid hex".into()))?;
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        return Ok(addr);
    }
    Err(SdkError::InvalidAddress(
        "expected Stl57... or 64-character hex".into(),
    ))
}

/// Lower-case 64-character hex, no prefix.
pub fn to_hex(addr: &[u8; 32]) -> String {
    hex::encode(addr)
}

fn base58_encode(input: &[u8]) -> String {
    let leading = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &b in input.iter().skip(leading) {
        let mut carry = b as usize;
        for d in digits.iter_mut() {
            carry += (*d as usize) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(leading + digits.len());
    for _ in 0..leading {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(BASE58_ALPHABET[*d as usize] as char);
    }
    out
}

fn base58_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    let leading = bytes.iter().take_while(|&&b| b == b'1').count();
    let mut out: Vec<u8> = Vec::new();
    for &c in &bytes[leading..] {
        let val = BASE58_ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| format!("invalid character {:?}", c as char))?;
        let mut carry = val;
        for b in out.iter_mut() {
            carry += (*b as usize) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    out.extend(std::iter::repeat_n(0u8, leading));
    out.reverse();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stl57_roundtrip() {
        let addr = [0xABu8; 32];
        let s = encode_stl57(&addr);
        assert!(s.starts_with("Stl57"));
        assert_eq!(parse_address(&s).unwrap(), addr);
        assert_eq!(parse_address(&to_hex(&addr)).unwrap(), addr);
        assert_eq!(
            parse_address(&format!("0x{}", to_hex(&addr))).unwrap(),
            addr
        );
    }

    #[test]
    fn typo_is_refused() {
        let addr = [0x11u8; 32];
        let mut s = encode_stl57(&addr);
        let last = s.pop().unwrap();
        s.push(if last == '1' { '2' } else { '1' });
        assert!(parse_address(&s).is_err());
    }
}
