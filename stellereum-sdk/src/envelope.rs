//! Canonical `PQ1` signature envelope (Falcon-512 only).
//!
//! Wire layout copied exactly from `stellereum/src/sharding/envelope.rs`
//! (`PqSignatureEnvelope::encode`, lines 109-146) and its strict decoder
//! (lines 171-260):
//!
//! ```text
//! "PQ1" | scheme(1) | implicit(1) | pk_len(2 LE) | [pubkey] |
//! [salt(16) if explicit] | sig_len(2 LE) | signature |
//! [chain_id(8 BE) if bound]
//! ```
//!
//! The SDK only mints Falcon-512 (`scheme = 0x02`) because that is the only
//! live scheme (`PqScheme::from_id` accepts only 2). Decoding also refuses
//! every other scheme id fail-closed, exactly like the node.

use crate::error::{Result, SdkError};
use crate::key::{
    CHAIN_SIG_HEADER, DEFAULT_SALT, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN, PQ_SCHEME_FALCON512,
};

/// Envelope magic (`stellereum/src/post_quantum.rs:124`).
pub const PQ_ENVELOPE_MAGIC: &[u8; 3] = b"PQ1";

/// How a transaction's public key travels on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeMode {
    /// `PQ1` with the full 897-byte public key and salt. First transaction
    /// from an address; the node charges `PQ_ACTIVATION_SURCHARGE_GAS` for it.
    Explicit,
    /// `PQ1` with the public key omitted. Only valid after the address's key
    /// is registered in the node's implicit-key registry; the surcharge does
    /// not apply.
    Implicit,
}

/// A decoded or under-construction `PQ1` envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqEnvelope {
    pub mode: EnvelopeMode,
    pub pubkey: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub salt: [u8; 16],
    pub chain_id: Option<u64>,
}

impl PqEnvelope {
    /// Explicit envelope with the default zero salt.
    pub fn explicit(pubkey: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            mode: EnvelopeMode::Explicit,
            pubkey: Some(pubkey),
            signature,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Explicit envelope bound to a chain id.
    pub fn explicit_with_chain(pubkey: Vec<u8>, signature: Vec<u8>, chain_id: u64) -> Self {
        let mut e = Self::explicit(pubkey, signature);
        e.chain_id = Some(chain_id);
        e
    }

    /// Implicit envelope (public key omitted from the wire).
    pub fn implicit(signature: Vec<u8>) -> Self {
        Self {
            mode: EnvelopeMode::Implicit,
            pubkey: None,
            signature,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Implicit envelope bound to a chain id.
    pub fn implicit_with_chain(signature: Vec<u8>, chain_id: u64) -> Self {
        let mut e = Self::implicit(signature);
        e.chain_id = Some(chain_id);
        e
    }

    /// True when this envelope carries a public key (activation).
    pub fn is_explicit(&self) -> bool {
        self.mode == EnvelopeMode::Explicit
    }

    /// Encode to the node's canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let explicit = self.is_explicit();
        let pk = if explicit {
            let Some(pk) = &self.pubkey else {
                return Err(SdkError::InvalidArgument(
                    "explicit envelope requires a public key".into(),
                ));
            };
            if pk.len() != FALCON512_PUBKEY_LEN {
                return Err(SdkError::InvalidArgument(format!(
                    "public key must be {FALCON512_PUBKEY_LEN} bytes"
                )));
            }
            Some(pk.as_slice())
        } else {
            if self.pubkey.is_some() {
                return Err(SdkError::InvalidArgument(
                    "implicit envelope must not carry a public key".into(),
                ));
            }
            None
        };
        if self.signature.len() != FALCON512_SIG_LEN {
            return Err(SdkError::InvalidArgument(format!(
                "Falcon-512 signature must be {FALCON512_SIG_LEN} bytes, got {}",
                self.signature.len()
            )));
        }
        if self.signature.first() != Some(&CHAIN_SIG_HEADER) {
            return Err(SdkError::InvalidArgument(
                "signature is not in the chain-canonical 0x29 framing".into(),
            ));
        }

        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(PQ_ENVELOPE_MAGIC);
        out.push(PQ_SCHEME_FALCON512);
        out.push(if explicit { 0 } else { 1 });
        match pk {
            Some(pk) => {
                out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
                out.extend_from_slice(pk);
                out.extend_from_slice(&self.salt);
            }
            None => out.extend_from_slice(&0u16.to_le_bytes()),
        }
        out.extend_from_slice(&(self.signature.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.signature);
        if let Some(cid) = self.chain_id {
            out.extend_from_slice(&cid.to_be_bytes());
        }
        Ok(out)
    }

    /// Exact encoded length.
    pub fn encoded_len(&self) -> usize {
        3 + 1
            + 1
            + 2
            + if self.is_explicit() {
                self.pubkey.as_ref().map_or(0, Vec::len) + 16
            } else {
                0
            }
            + 2
            + self.signature.len()
            + if self.chain_id.is_some() { 8 } else { 0 }
    }

    /// Strict decode. Refuses every framing the node refuses: wrong magic,
    /// scheme != 2, flag byte not 0/1, implicit with a key, wrong key or
    /// signature length, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 7 {
            return Err(SdkError::Decode("envelope too short".into()));
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err(SdkError::Decode("missing PQ1 magic".into()));
        }
        if bytes[3] != PQ_SCHEME_FALCON512 {
            return Err(SdkError::Decode(format!(
                "unsupported scheme id {} (only Falcon-512/0x02 is live)",
                bytes[3]
            )));
        }
        let flag = bytes[4];
        if flag > 1 {
            return Err(SdkError::Decode("flag byte must be 0 or 1".into()));
        }
        let implicit = flag == 1;
        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
        let mut cursor = 7;
        let mut pubkey = None;
        let mut salt = DEFAULT_SALT;
        if implicit {
            if pk_len != 0 {
                return Err(SdkError::Decode(
                    "implicit envelope must not carry a public key".into(),
                ));
            }
        } else {
            if pk_len != FALCON512_PUBKEY_LEN {
                return Err(SdkError::Decode(format!(
                    "explicit public key must be {FALCON512_PUBKEY_LEN} bytes, got {pk_len}"
                )));
            }
            if bytes.len() < cursor + pk_len + 16 + 2 {
                return Err(SdkError::Decode("truncated explicit envelope".into()));
            }
            pubkey = Some(bytes[cursor..cursor + pk_len].to_vec());
            cursor += pk_len;
            salt.copy_from_slice(&bytes[cursor..cursor + 16]);
            cursor += 16;
        }
        if bytes.len() < cursor + 2 {
            return Err(SdkError::Decode("truncated signature length".into()));
        }
        let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        if sig_len != FALCON512_SIG_LEN {
            return Err(SdkError::Decode(format!(
                "signature must be {FALCON512_SIG_LEN} bytes, got {sig_len}"
            )));
        }
        if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
            return Err(SdkError::Decode("truncated signature bytes".into()));
        }
        let signature = bytes[cursor..cursor + sig_len].to_vec();
        cursor += sig_len;
        let chain_id = if bytes.len() == cursor + 8 {
            Some(u64::from_be_bytes(
                bytes[cursor..cursor + 8].try_into().expect("8-byte slice"),
            ))
        } else {
            None
        };
        Ok(Self {
            mode: if implicit {
                EnvelopeMode::Implicit
            } else {
                EnvelopeMode::Explicit
            },
            pubkey,
            signature,
            salt,
            chain_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_roundtrip_with_chain() {
        let e = PqEnvelope::explicit_with_chain(vec![9u8; 897], vec![0x29u8; 666], 5757);
        let bytes = e.encode().unwrap();
        assert_eq!(bytes.len(), e.encoded_len());
        assert_eq!(PqEnvelope::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn implicit_roundtrip() {
        let e = PqEnvelope::implicit(vec![0x29u8; 666]);
        let bytes = e.encode().unwrap();
        assert_eq!(PqEnvelope::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn trailing_bytes_refused() {
        let e = PqEnvelope::implicit(vec![0x29u8; 666]);
        let mut bytes = e.encode().unwrap();
        bytes.push(0);
        assert!(PqEnvelope::decode(&bytes).is_err());
    }
}
