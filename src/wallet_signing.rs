//! Wallet Signature Standard for Stellereum (audit P2 item 15).
//!
//! The wallet used to sign with a proprietary SHA-256 seed derivation that was
//! "incompatible with anything but its own CLI", and there was no documented
//! standard for how a wallet signs a transaction, a message, or a contract
//! call. This module IS that standard. Reference models: EIP-191/EIP-712
//! (Ethereum `personal_sign` / typed data), NEP-413 (NEAR message signing),
//! TON's signed-payload conventions.
//!
//! What is standardized here (and ONLY this):
//!
//! * the MESSAGE preimage, byte-for-byte (EIP-191-style, but with the chain id
//!   bound in, so a testnet signature is never valid on mainnet);
//! * `sign_message` / `verify_message` for Ed25519, Falcon-512 and Hybrid;
//! * `sign_typed_data` / `verify_typed_data` for STRUCTURED contract calls: a
//!   canonical JSON encoding (sorted keys, explicit types) of
//!   `{ contract, method, args, value, nonce, chain_id }`, so a wallet can show
//!   the user exactly what they sign (EIP-712-style readable signing);
//! * the [`WalletSignature`] envelope: version byte + scheme id + public key +
//!   signature bytes, with strict fail-closed decoding.
//!
//! What is NOT changed: the transaction format and the address format. This is
//! purely the message-signing layer. Raw 32-byte addresses stay raw 32-byte
//! addresses (hex on the wire); Ed25519 addresses are the public key itself,
//! Falcon-512/Hybrid addresses are `derive_pq_address(scheme, pubkey, ZERO_SALT)`.
//!
//! Full prose, test vectors and the RPC/CLI surface: `docs/WALLET_SIGNING.md`.

use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, FalconKeypair, PqScheme, DEFAULT_SALT,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

// ============================================================================
// Constants
// ============================================================================

/// Human-readable prefix every signed message starts with (EIP-191-style).
///
/// The exact bytes are `Stellereum Signed Message:\n` (27 bytes, trailing LF
/// included). A signature over a Stellereum preimage can never be mistaken for
/// a raw transaction signature or a foreign chain's `personal_sign`.
pub const STELL_MESSAGE_PREFIX: &[u8] = b"Stellereum Signed Message:\n";

/// Domain tag for PLAIN messages. Binds the preimage to "a human-readable
/// message", as opposed to structured contract-call data below.
pub const STELL_MESSAGE_DOMAIN_TAG: &[u8] = b"STELL-MSGSIG-V1";

/// Domain tag for STRUCTURED (typed-data) contract calls. Binds the preimage
/// to "a contract call the wallet displayed", so a blind message signature can
/// never be replayed as a contract authorization and vice versa.
pub const STELL_TYPED_DATA_DOMAIN_TAG: &[u8] = b"STELL-TYPEDDATA-V1";

/// Envelope version. Version 0 was never issued; the first (and only) standard
/// envelope is version 1. Decoders MUST refuse anything else fail-closed.
pub const WALLET_SIG_VERSION: u8 = 1;

/// Salt used for PQ address derivation in wallet signing. Wallet signatures
/// always pin the zero salt ([`DEFAULT_SALT`]) so the address is a pure
/// function of `(scheme, pubkey)` and any verifier can re-derive it without
/// extra parameters.
pub const WALLET_SIGN_SALT: [u8; 16] = DEFAULT_SALT;

/// Maximum message that `sign_message` will sign (64 KiB). Larger payloads
/// must be hashed by the caller and the digest signed as typed data instead.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Maximum serialized canonical typed-data JSON (64 KiB). Same rationale.
pub const MAX_TYPED_DATA_BYTES: usize = 64 * 1024;

/// Maximum `method` name length in typed data (256 bytes, like governance titles).
pub const MAX_METHOD_BYTES: usize = 256;

// ============================================================================
// Preimage
// ============================================================================

/// Canonical MESSAGE preimage, byte-for-byte:
///
/// ```text
/// STELL_MESSAGE_PREFIX (27 B, "Stellereum Signed Message:\n")
/// || domain tag (15 B, "STELL-MSGSIG-V1" or "STELL-TYPEDDATA-V1")
/// || chain_id (u64 BE, 8 B)
/// || message_len (u64 BE, 8 B — length of the message bytes that follow)
/// || message bytes
/// ```
///
/// The chain id binds the signature to one deployment: a signature minted for
/// chain 5757 (testnet) verifies as INVALID on any other chain id, because the
/// verifier rebuilds the preimage with its own chain id. The length prefix
/// makes the framing unambiguous (no `prefix || a || b` vs `prefix || ab`
/// collisions).
pub fn message_preimage(chain_id: u64, message: &[u8]) -> Vec<u8> {
    message_preimage_with_domain(STELL_MESSAGE_DOMAIN_TAG, chain_id, message)
}

fn message_preimage_with_domain(domain: &[u8], chain_id: u64, message: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(STELL_MESSAGE_PREFIX.len() + domain.len() + 8 + 8 + message.len());
    out.extend_from_slice(STELL_MESSAGE_PREFIX);
    out.extend_from_slice(domain);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(&(message.len() as u64).to_be_bytes());
    out.extend_from_slice(message);
    out
}

// ============================================================================
// Canonical typed data (EIP-712-style readable signing)
// ============================================================================

/// A structured contract call a wallet shows the user before signing.
///
/// All integer fields are encoded as DECIMAL STRINGS in the canonical JSON
/// (the RPC convention: `u64` does not survive a JavaScript `Number`), so the
/// types are explicit and the encoding is identical in every JSON library.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedCallData {
    /// 32-byte contract address (hex, `0x`-prefixed, lowercase in canonical form).
    pub contract: String,
    /// Contract method name.
    pub method: String,
    /// Method arguments (any JSON; objects are key-sorted recursively).
    pub args: Value,
    /// Native value attached, as a decimal string.
    pub value: String,
    /// Sender nonce, as a decimal string.
    pub nonce: String,
    /// Chain id the call is authorized for, as a decimal string.
    pub chain_id: String,
}

impl TypedCallData {
    /// Build from native parts, validating shapes fail-closed.
    pub fn new(
        contract: &[u8; 32],
        method: &str,
        args: Value,
        value: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Result<Self, String> {
        if method.is_empty() {
            return Err("typed data: method must not be empty".to_string());
        }
        if method.len() > MAX_METHOD_BYTES {
            return Err(format!(
                "typed data: method longer than {MAX_METHOD_BYTES} bytes"
            ));
        }
        Ok(Self {
            contract: format!("0x{}", hex::encode(contract)),
            method: method.to_string(),
            args,
            value: value.to_string(),
            nonce: nonce.to_string(),
            chain_id: chain_id.to_string(),
        })
    }

    /// The chain id as a number (parsed from the decimal string).
    pub fn chain_id_u64(&self) -> Result<u64, String> {
        self.chain_id
            .parse::<u64>()
            .map_err(|_| "typed data: chain_id is not a u64 decimal string".to_string())
    }
}

/// Render a `serde_json::Value` canonically: object keys sorted recursively,
/// no whitespace, JSON string escaping per RFC 8259.
///
/// Two JSON objects with the same content in different key order produce
/// byte-identical output (pinned by test).
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).expect("a string always serializes"),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            // BTreeMap sorts keys; collect first so iteration order is canonical
            // regardless of the underlying Map implementation.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            let mut out = String::from("{");
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("a key always serializes"));
                out.push(':');
                out.push_str(&canonical_json(v));
            }
            out.push('}');
            out
        }
    }
}

/// Canonical JSON encoding of typed call data. Fixed key order (sorted):
///
/// ```json
/// {"args":…,"chain_id":"…","contract":"0x…","method":"…","nonce":"…","value":"…"}
/// ```
///
/// `args` is embedded in canonical form (see [`canonical_json`]).
pub fn canonical_typed_data_json(data: &TypedCallData) -> String {
    format!(
        "{{\"args\":{},\"chain_id\":{},\"contract\":{},\"method\":{},\"nonce\":{},\"value\":{}}}",
        canonical_json(&data.args),
        serde_json::to_string(&data.chain_id).expect("a string always serializes"),
        serde_json::to_string(&data.contract).expect("a string always serializes"),
        serde_json::to_string(&data.method).expect("a string always serializes"),
        serde_json::to_string(&data.nonce).expect("a string always serializes"),
        serde_json::to_string(&data.value).expect("a string always serializes"),
    )
}

/// Typed-data preimage: the canonical JSON bytes framed exactly like a message
/// but under the typed-data domain tag (see [`message_preimage`]).
pub fn typed_data_preimage(data: &TypedCallData) -> Result<Vec<u8>, String> {
    let chain_id = data.chain_id_u64()?;
    let canonical = canonical_typed_data_json(data);
    if canonical.len() > MAX_TYPED_DATA_BYTES {
        return Err(format!(
            "typed data: canonical JSON longer than {MAX_TYPED_DATA_BYTES} bytes"
        ));
    }
    Ok(message_preimage_with_domain(
        STELL_TYPED_DATA_DOMAIN_TAG,
        chain_id,
        canonical.as_bytes(),
    ))
}

// ============================================================================
// Envelope
// ============================================================================

/// The standard wallet signature envelope.
///
/// Wire layout, byte-for-byte:
///
/// ```text
/// version   (1 B)  = 0x01 (WALLET_SIG_VERSION)
/// scheme    (1 B)  = 0x01 Ed25519 | 0x02 Falcon-512 | 0x04 Hybrid (0x03 refused)
/// pubkey_len(u16 BE, 2 B) = scheme.pubkey_size() exactly
/// pubkey    (pubkey_len B)
/// sig_len   (u16 BE, 2 B) = scheme.signature_size() exactly
/// signature (sig_len B)
/// ```
///
/// The public key rides in the envelope because a 32-byte Falcon-512/Hybrid
/// ADDRESS is a hash (`derive_pq_address`) — it cannot verify on its own.
/// The verifier re-derives the address from `(scheme, pubkey)` and compares it
/// to the claimed address BEFORE checking the signature, so a signature under
/// key K can never be presented as a signature by address A != addr(K).
///
/// Sizes on the wire: Ed25519 102 B, Falcon-512 1569 B, Hybrid 1665 B.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletSignature {
    /// Always [`WALLET_SIG_VERSION`].
    pub version: u8,
    /// [`PqScheme::Ed25519`] | [`PqScheme::Falcon512`] | [`PqScheme::Hybrid`].
    /// `MlDsa44` (0x03) is refused fail-closed at decode time.
    pub scheme: PqScheme,
    /// Canonical public key bytes (`scheme.pubkey_size()` long).
    pub pubkey: Vec<u8>,
    /// Signature bytes over the preimage (`scheme.signature_size()` long).
    pub signature: Vec<u8>,
}

impl WalletSignature {
    /// Encode to the wire form above.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 2 + self.pubkey.len() + 2 + self.signature.len());
        out.push(self.version);
        out.push(self.scheme.id());
        out.extend_from_slice(&(self.pubkey.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Hex of [`WalletSignature::encode`] (what the RPC and CLI pass around).
    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }

    /// Strict fail-closed decode: version must be 0x01, scheme must be a live
    /// scheme (0x03 refused loudly), lengths must match the scheme's canonical
    /// sizes EXACTLY, and no trailing byte is tolerated.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 {
            return Err("wallet signature: envelope shorter than 6 bytes".to_string());
        }
        let version = bytes[0];
        if version != WALLET_SIG_VERSION {
            return Err(format!(
                "wallet signature: unsupported version {version:#04x}, expected {:#04x}",
                WALLET_SIG_VERSION
            ));
        }
        // from_id refuses 0x03 (ML-DSA-44, forgeable verifier) and unknown ids.
        let scheme = PqScheme::from_id(bytes[1])?;
        let mut cur = 2usize;
        let take =
            |bytes: &[u8], cur: &mut usize, n: usize, what: &str| -> Result<Vec<u8>, String> {
                if bytes.len() < *cur + n {
                    return Err(format!("wallet signature: envelope truncated in {what}"));
                }
                let v = bytes[*cur..*cur + n].to_vec();
                *cur += n;
                Ok(v)
            };
        let mut len = [0u8; 2];
        len.copy_from_slice(&take(bytes, &mut cur, 2, "pubkey_len")?);
        let pubkey_len = u16::from_be_bytes(len) as usize;
        if pubkey_len != scheme.pubkey_size() {
            return Err(format!(
                "wallet signature: pubkey_len {pubkey_len} != {} for {scheme}",
                scheme.pubkey_size()
            ));
        }
        let pubkey = take(bytes, &mut cur, pubkey_len, "pubkey")?;
        // Extra fail-closed guard for Ed25519: a non-curve point is not a key.
        // Audit HIGH-1: also refuse small-order keys (`is_weak`) — they parse
        // but verify malleably; consensus strictness must hold here too.
        if scheme == PqScheme::Ed25519 {
            let vk_bytes = <[u8; 32]>::try_from(pubkey.as_slice()).expect("len checked");
            match VerifyingKey::from_bytes(&vk_bytes) {
                Err(_) => {
                    return Err(
                        "wallet signature: Ed25519 public key is not a valid curve point"
                            .to_string(),
                    )
                }
                Ok(vk) if vk.is_weak() => {
                    return Err(
                        "wallet signature: Ed25519 public key is small-order".to_string(),
                    )
                }
                Ok(_) => {}
            }
        }
        let mut slen = [0u8; 2];
        slen.copy_from_slice(&take(bytes, &mut cur, 2, "sig_len")?);
        let sig_len = u16::from_be_bytes(slen) as usize;
        if sig_len != scheme.signature_size() {
            return Err(format!(
                "wallet signature: sig_len {sig_len} != {} for {scheme}",
                scheme.signature_size()
            ));
        }
        let signature = take(bytes, &mut cur, sig_len, "signature")?;
        if cur != bytes.len() {
            return Err("wallet signature: trailing bytes after signature".to_string());
        }
        Ok(Self {
            version,
            scheme,
            pubkey,
            signature,
        })
    }

    /// [`WalletSignature::decode`] from hex.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| format!("wallet signature: bad hex: {e}"))?;
        Self::decode(&bytes)
    }

    /// The address this signature claims to be from: Ed25519 = the public key
    /// itself; Falcon-512/Hybrid = `derive_pq_address(scheme, pubkey, ZERO_SALT)`.
    pub fn claimed_address(&self) -> [u8; 32] {
        match self.scheme {
            PqScheme::Ed25519 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&self.pubkey);
                a
            }
            PqScheme::Falcon512 | PqScheme::Hybrid | PqScheme::MlDsa44 => {
                derive_pq_address(self.scheme, &self.pubkey, &WALLET_SIGN_SALT)
            }
        }
    }
}

// ============================================================================
// Signing keys
// ============================================================================

/// A wallet signing key for one of the three live schemes.
///
/// * Ed25519: 32-byte seed (the same seed the wallet module derives accounts from).
/// * Falcon-512: a full [`FalconKeypair`] (897-byte canonical public key).
/// * Hybrid: both — the preimage is signed with each and the signatures
///   concatenated (Ed first, Falcon second), exactly like
///   [`verify_pq_signature`] expects.
pub enum WalletSigningKey {
    /// Classic fast Ed25519.
    Ed25519 { seed: [u8; 32] },
    /// Post-quantum Falcon-512.
    Falcon { keypair: FalconKeypair },
    /// Hybrid dual-signature (Ed25519 + Falcon-512).
    Hybrid {
        ed_seed: [u8; 32],
        falcon: FalconKeypair,
    },
}

impl WalletSigningKey {
    /// Build an Ed25519 key from a 32-byte seed.
    pub fn ed25519(seed: [u8; 32]) -> Self {
        Self::Ed25519 { seed }
    }

    /// Build a Falcon-512 key deterministically from a 32-byte seed
    /// (reproducible; the same seed always yields the same keypair).
    pub fn falcon_from_seed(seed: &[u8; 32]) -> Self {
        Self::Falcon {
            keypair: FalconKeypair::generate_from_seed_bytes(seed),
        }
    }

    /// Build a Hybrid key from an Ed25519 seed and a Falcon-512 seed.
    pub fn hybrid(ed_seed: [u8; 32], falcon_seed: &[u8; 32]) -> Self {
        Self::Hybrid {
            ed_seed,
            falcon: FalconKeypair::generate_from_seed_bytes(falcon_seed),
        }
    }

    /// Which scheme this key signs with.
    pub fn scheme(&self) -> PqScheme {
        match self {
            Self::Ed25519 { .. } => PqScheme::Ed25519,
            Self::Falcon { .. } => PqScheme::Falcon512,
            Self::Hybrid { .. } => PqScheme::Hybrid,
        }
    }

    /// Canonical public key bytes.
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519 { seed } => SigningKey::from_bytes(seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            Self::Falcon { keypair } => keypair.public_key().to_vec(),
            Self::Hybrid { ed_seed, falcon } => {
                let mut pk = Vec::with_capacity(crate::post_quantum::HYBRID_PUBKEY_LEN);
                pk.extend_from_slice(&SigningKey::from_bytes(ed_seed).verifying_key().to_bytes());
                pk.extend_from_slice(falcon.public_key());
                pk
            }
        }
    }

    /// The wallet address for this key (what `verify_message` checks against).
    pub fn address(&self) -> [u8; 32] {
        match self.scheme() {
            PqScheme::Ed25519 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&self.pubkey_bytes());
                a
            }
            s => derive_pq_address(s, &self.pubkey_bytes(), &WALLET_SIGN_SALT),
        }
    }

    fn sign_preimage(&self, preimage: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Ed25519 { seed } => {
                let sk = SigningKey::from_bytes(seed);
                Ok(sk.sign(preimage).to_bytes().to_vec())
            }
            Self::Falcon { keypair } => {
                let sig = keypair.sign(preimage);
                if sig.len() != crate::post_quantum::FALCON512_SIG_LEN {
                    return Err("wallet signing: Falcon-512 signer refused the key".to_string());
                }
                Ok(sig)
            }
            Self::Hybrid { ed_seed, falcon } => {
                let sk = SigningKey::from_bytes(ed_seed);
                let mut sig = Vec::with_capacity(crate::post_quantum::HYBRID_SIG_LEN);
                sig.extend_from_slice(&sk.sign(preimage).to_bytes());
                let fsig = falcon.sign(preimage);
                if fsig.len() != crate::post_quantum::FALCON512_SIG_LEN {
                    return Err("wallet signing: Falcon-512 signer refused the key".to_string());
                }
                sig.extend_from_slice(&fsig);
                Ok(sig)
            }
        }
    }

    /// Sign an arbitrary message under `chain_id`. Fails closed when the
    /// message exceeds [`MAX_MESSAGE_BYTES`].
    pub fn sign_message(&self, chain_id: u64, message: &[u8]) -> Result<WalletSignature, String> {
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(format!(
                "wallet signing: message longer than {MAX_MESSAGE_BYTES} bytes"
            ));
        }
        let preimage = message_preimage(chain_id, message);
        let scheme = self.scheme();
        let pubkey = self.pubkey_bytes();
        let signature = self.sign_preimage(&preimage)?;
        debug_assert_eq!(signature.len(), scheme.signature_size());
        Ok(WalletSignature {
            version: WALLET_SIG_VERSION,
            scheme,
            pubkey,
            signature,
        })
    }

    /// Sign structured contract-call data (the wallet displays
    /// [`canonical_typed_data_json`] to the user first).
    ///
    /// Returns the signature AND the canonical JSON that was signed, so the
    /// caller can show/store exactly what the bytes commit to.
    pub fn sign_typed_data(
        &self,
        data: &TypedCallData,
    ) -> Result<(WalletSignature, String), String> {
        let preimage = typed_data_preimage(data)?;
        let canonical = canonical_typed_data_json(data);
        let scheme = self.scheme();
        let pubkey = self.pubkey_bytes();
        let signature = self.sign_preimage(&preimage)?;
        debug_assert_eq!(signature.len(), scheme.signature_size());
        Ok((
            WalletSignature {
                version: WALLET_SIG_VERSION,
                scheme,
                pubkey,
                signature,
            },
            canonical,
        ))
    }
}

// ============================================================================
// Verification (public: needs no secret, no auth)
// ============================================================================

/// Verify a message signature against a claimed address and chain id.
///
/// Rebuilds the preimage with the CALLER's `chain_id` (never trusts one from
/// the envelope — the envelope carries none), re-derives the address from the
/// envelope's `(scheme, pubkey)` and compares it to `address`, then checks the
/// signature. Any mismatch — wrong chain, tampered message, wrong address,
/// malformed envelope — is `false` (never an error: verification is total).
pub fn verify_message(
    address: &[u8; 32],
    chain_id: u64,
    message: &[u8],
    sig: &WalletSignature,
) -> bool {
    if sig.version != WALLET_SIG_VERSION {
        return false;
    }
    if sig.scheme.is_disabled() {
        return false;
    }
    if sig.pubkey.len() != sig.scheme.pubkey_size()
        || sig.signature.len() != sig.scheme.signature_size()
    {
        return false;
    }
    if sig.claimed_address() != *address {
        return false;
    }
    let preimage = message_preimage(chain_id, message);
    verify_pq_signature(sig.scheme, &sig.pubkey, &preimage, &sig.signature)
}

/// Verify a typed-data signature. The caller passes the STRUCTURED fields
/// (rebuilt from what the user was shown); the canonical JSON is re-encoded
/// locally and the preimage rebuilt with the caller's `chain_id`.
pub fn verify_typed_data(address: &[u8; 32], data: &TypedCallData, sig: &WalletSignature) -> bool {
    if sig.version != WALLET_SIG_VERSION {
        return false;
    }
    if sig.scheme.is_disabled() {
        return false;
    }
    if sig.pubkey.len() != sig.scheme.pubkey_size()
        || sig.signature.len() != sig.scheme.signature_size()
    {
        return false;
    }
    if sig.claimed_address() != *address {
        return false;
    }
    let preimage = match typed_data_preimage(data) {
        Ok(p) => p,
        Err(_) => return false,
    };
    verify_pq_signature(sig.scheme, &sig.pubkey, &preimage, &sig.signature)
}

/// Parse one hex-or-UTF8 message parameter pair from RPC/CLI input.
///
/// Exactly one of `message` (UTF-8 string) / `message_hex` (hex bytes) must be
/// present. Returns the raw message bytes.
pub fn parse_message_param(
    message: Option<&str>,
    message_hex: Option<&str>,
) -> Result<Vec<u8>, String> {
    match (message, message_hex) {
        (Some(_), Some(_)) => Err("pass exactly one of 'message' / 'message_hex'".to_string()),
        (None, None) => {
            Err("missing message: pass 'message' (UTF-8) or 'message_hex' (hex)".to_string())
        }
        (Some(m), None) => {
            if m.len() > MAX_MESSAGE_BYTES {
                return Err(format!("message longer than {MAX_MESSAGE_BYTES} bytes"));
            }
            Ok(m.as_bytes().to_vec())
        }
        (None, Some(h)) => {
            let h = h.strip_prefix("0x").unwrap_or(h);
            let bytes = hex::decode(h).map_err(|e| format!("bad message_hex: {e}"))?;
            if bytes.len() > MAX_MESSAGE_BYTES {
                return Err(format!("message longer than {MAX_MESSAGE_BYTES} bytes"));
            }
            Ok(bytes)
        }
    }
}

/// Parse a `u64` that may be a JSON number or a decimal string (the RPC
/// convention for anything that does not survive a JavaScript `Number`).
pub fn parse_u64_param(v: &Value) -> Result<u64, String> {
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        return s
            .parse::<u64>()
            .map_err(|_| format!("not a u64 decimal string: {s:?}"));
    }
    Err("not a u64 (number or decimal string)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_MAIN: u64 = 5757;
    const CHAIN_OTHER: u64 = 5758;

    #[test]
    fn preimage_layout_is_byte_exact() {
        // "hello" on chain 5757. Layout:
        // PREFIX(27) || DOMAIN(15) || chain BE(8) || len BE(8) || msg
        let p = message_preimage(CHAIN_MAIN, b"hello");
        assert_eq!(p.len(), 27 + 15 + 8 + 8 + 5);
        assert_eq!(&p[..27], b"Stellereum Signed Message:\n");
        assert_eq!(&p[27..42], b"STELL-MSGSIG-V1");
        assert_eq!(&p[42..50], &CHAIN_MAIN.to_be_bytes());
        assert_eq!(&p[50..58], &5u64.to_be_bytes());
        assert_eq!(&p[58..], b"hello");
    }

    #[test]
    fn ed25519_round_trip() {
        let key = WalletSigningKey::ed25519([0x42u8; 32]);
        let addr = key.address();
        // Ed25519 address IS the public key.
        assert_eq!(
            addr,
            SigningKey::from_bytes(&[0x42u8; 32])
                .verifying_key()
                .to_bytes()
        );
        let sig = key
            .sign_message(CHAIN_MAIN, b"hello stellereum")
            .expect("signs");
        assert_eq!(sig.scheme, PqScheme::Ed25519);
        assert_eq!(sig.encode().len(), 102);
        assert!(verify_message(&addr, CHAIN_MAIN, b"hello stellereum", &sig));
        // Envelope round trip.
        let back = WalletSignature::decode(&sig.encode()).expect("decodes");
        assert_eq!(back, sig);
        assert!(verify_message(
            &addr,
            CHAIN_MAIN,
            b"hello stellereum",
            &back
        ));
    }

    #[test]
    fn falcon512_round_trip() {
        let key = WalletSigningKey::falcon_from_seed(&[0x77u8; 32]);
        let addr = key.address();
        assert_eq!(
            addr,
            derive_pq_address(PqScheme::Falcon512, &key.pubkey_bytes(), &WALLET_SIGN_SALT)
        );
        let sig = key
            .sign_message(CHAIN_MAIN, b"hello stellereum")
            .expect("signs");
        assert_eq!(sig.scheme, PqScheme::Falcon512);
        assert_eq!(sig.encode().len(), 1569);
        assert!(verify_message(&addr, CHAIN_MAIN, b"hello stellereum", &sig));
        let back = WalletSignature::from_hex(&sig.to_hex()).expect("decodes");
        assert!(verify_message(
            &addr,
            CHAIN_MAIN,
            b"hello stellereum",
            &back
        ));
    }

    #[test]
    fn hybrid_round_trip() {
        let key = WalletSigningKey::hybrid([0x42u8; 32], &[0x77u8; 32]);
        let addr = key.address();
        assert_eq!(
            addr,
            derive_pq_address(PqScheme::Hybrid, &key.pubkey_bytes(), &WALLET_SIGN_SALT)
        );
        let sig = key
            .sign_message(CHAIN_MAIN, b"hello stellereum")
            .expect("signs");
        assert_eq!(sig.scheme, PqScheme::Hybrid);
        assert_eq!(sig.encode().len(), 1665);
        assert!(verify_message(&addr, CHAIN_MAIN, b"hello stellereum", &sig));
        // The hybrid address differs from either half's address.
        let ed_addr = WalletSigningKey::ed25519([0x42u8; 32]).address();
        assert_ne!(addr, ed_addr);
    }

    #[test]
    fn cross_scheme_matrix() {
        // Every scheme verifies its own signatures; no scheme verifies another's
        // message/signature pair against a mismatched address.
        let keys = [
            WalletSigningKey::ed25519([0x11u8; 32]),
            WalletSigningKey::falcon_from_seed(&[0x22u8; 32]),
            WalletSigningKey::hybrid([0x33u8; 32], &[0x44u8; 32]),
        ];
        let msg = b"cross-scheme matrix";
        let sigs: Vec<_> = keys
            .iter()
            .map(|k| k.sign_message(CHAIN_MAIN, msg).expect("signs"))
            .collect();
        for (k, s) in keys.iter().zip(sigs.iter()) {
            assert!(verify_message(&k.address(), CHAIN_MAIN, msg, s));
        }
        // Cross-address presentation fails: sig[0] (Ed) claimed as falcon addr.
        assert!(!verify_message(
            &keys[1].address(),
            CHAIN_MAIN,
            msg,
            &sigs[0]
        ));
        assert!(!verify_message(
            &keys[0].address(),
            CHAIN_MAIN,
            msg,
            &sigs[1]
        ));
        assert!(!verify_message(
            &keys[0].address(),
            CHAIN_MAIN,
            msg,
            &sigs[2]
        ));
    }

    #[test]
    fn chain_binding_a_testnet_signature_is_invalid_elsewhere() {
        for key in [
            WalletSigningKey::ed25519([0x42u8; 32]),
            WalletSigningKey::falcon_from_seed(&[0x42u8; 32]),
            WalletSigningKey::hybrid([0x42u8; 32], &[0x43u8; 32]),
        ] {
            let addr = key.address();
            let sig = key
                .sign_message(CHAIN_MAIN, b"move 1 STELL")
                .expect("signs");
            assert!(verify_message(&addr, CHAIN_MAIN, b"move 1 STELL", &sig));
            assert!(
                !verify_message(&addr, CHAIN_OTHER, b"move 1 STELL", &sig),
                "chain-id binding failed for {:?}",
                key.scheme()
            );
            assert!(!verify_message(&addr, 1, b"move 1 STELL", &sig));
        }
    }

    #[test]
    fn tampered_message_fails_for_all_schemes() {
        for key in [
            WalletSigningKey::ed25519([0x42u8; 32]),
            WalletSigningKey::falcon_from_seed(&[0x42u8; 32]),
            WalletSigningKey::hybrid([0x42u8; 32], &[0x43u8; 32]),
        ] {
            let addr = key.address();
            let sig = key.sign_message(CHAIN_MAIN, b"pay alice 1").expect("signs");
            assert!(!verify_message(&addr, CHAIN_MAIN, b"pay alice 2", &sig));
            assert!(!verify_message(&addr, CHAIN_MAIN, b"", &sig));
            assert!(!verify_message(&addr, CHAIN_MAIN, b"pay alice 1 ", &sig));
        }
    }

    #[test]
    fn envelope_decoding_is_strict_fail_closed() {
        let key = WalletSigningKey::ed25519([0x42u8; 32]);
        let sig = key.sign_message(CHAIN_MAIN, b"x").expect("signs");
        let enc = sig.encode();
        // Trailing byte.
        let mut trailing = enc.clone();
        trailing.push(0x00);
        assert!(WalletSignature::decode(&trailing).is_err());
        // Truncated.
        assert!(WalletSignature::decode(&enc[..enc.len() - 1]).is_err());
        assert!(WalletSignature::decode(&[]).is_err());
        // Wrong version.
        let mut bad_ver = enc.clone();
        bad_ver[0] = 0x02;
        assert!(WalletSignature::decode(&bad_ver).is_err());
        // Disabled scheme 0x03.
        let mut bad_scheme = enc.clone();
        bad_scheme[1] = 0x03;
        assert!(WalletSignature::decode(&bad_scheme).is_err());
        // Unknown scheme.
        let mut unknown = enc.clone();
        unknown[1] = 0x09;
        assert!(WalletSignature::decode(&unknown).is_err());
        // Swapped length prefix.
        let mut bad_len = enc.clone();
        bad_len[2] = 0x00;
        bad_len[3] = 0x20 + 1;
        assert!(WalletSignature::decode(&bad_len).is_err());
        // Bad hex.
        assert!(WalletSignature::from_hex("zz").is_err());
    }

    #[test]
    fn typed_data_encoding_is_canonical() {
        let contract = [0xABu8; 32];
        let args_a: Value =
            serde_json::json!({"to": "alice", "amount": 100, "nested": {"z": 1, "a": 2}});
        let args_b: Value =
            serde_json::json!({"nested": {"a": 2, "z": 1}, "amount": 100, "to": "alice"});
        // NOTE: serde_json's default Map is a BTreeMap, so both literals already
        // carry sorted keys. The canonicalizer must ALSO sort (it cannot rely on
        // that): parse from raw strings with adversarial key order instead.
        let args_c: Value =
            serde_json::from_str(r#"{"to":"alice","nested":{"z":1,"a":2},"amount":100}"#).unwrap();
        let args_d: Value =
            serde_json::from_str(r#"{"amount":100,"to":"alice","nested":{"a":2,"z":1}}"#).unwrap();
        let da =
            TypedCallData::new(&contract, "transfer", args_a, 1000, 7, CHAIN_MAIN).expect("builds");
        let db =
            TypedCallData::new(&contract, "transfer", args_b, 1000, 7, CHAIN_MAIN).expect("builds");
        let dc =
            TypedCallData::new(&contract, "transfer", args_c, 1000, 7, CHAIN_MAIN).expect("builds");
        let dd =
            TypedCallData::new(&contract, "transfer", args_d, 1000, 7, CHAIN_MAIN).expect("builds");
        let ja = canonical_typed_data_json(&da);
        let jb = canonical_typed_data_json(&db);
        assert_eq!(ja, jb);
        assert_eq!(ja, canonical_typed_data_json(&dc));
        assert_eq!(ja, canonical_typed_data_json(&dd));
        assert_eq!(
            ja,
            format!(
                "{{\"args\":{{\"amount\":100,\"nested\":{{\"a\":2,\"z\":1}},\"to\":\"alice\"}},\"chain_id\":\"{CHAIN_MAIN}\",\"contract\":\"0x{}\",\"method\":\"transfer\",\"nonce\":\"7\",\"value\":\"1000\"}}",
                hex::encode(contract)
            )
        );
        // ... and the two orderings sign to the SAME bytes.
        let key = WalletSigningKey::ed25519([0x42u8; 32]);
        let (sa, ca) = key.sign_typed_data(&da).expect("signs");
        let (sb, cb) = key.sign_typed_data(&db).expect("signs");
        assert_eq!(ca, cb);
        assert_eq!(sa.signature, sb.signature);
        assert!(verify_typed_data(&key.address(), &da, &sa));
        assert!(verify_typed_data(&key.address(), &db, &sb));
    }

    #[test]
    fn typed_data_round_trips_all_schemes_and_binds_chain() {
        let contract = [0x01u8; 32];
        let data = TypedCallData::new(
            &contract,
            "place_order",
            serde_json::json!({"pair": 1, "side": "buy"}),
            500,
            3,
            CHAIN_MAIN,
        )
        .expect("builds");
        for key in [
            WalletSigningKey::ed25519([0x42u8; 32]),
            WalletSigningKey::falcon_from_seed(&[0x42u8; 32]),
            WalletSigningKey::hybrid([0x42u8; 32], &[0x43u8; 32]),
        ] {
            let addr = key.address();
            let (sig, canonical) = key.sign_typed_data(&data).expect("signs");
            assert!(
                verify_typed_data(&addr, &data, &sig),
                "scheme {:?}",
                key.scheme()
            );
            // Same fields on another chain fail.
            let mut other = data.clone();
            other.chain_id = CHAIN_OTHER.to_string();
            assert!(!verify_typed_data(&addr, &other, &sig));
            // Tampered display fails: what the user saw is not what was signed.
            let mut tampered = data.clone();
            tampered.value = "501".to_string();
            assert!(!verify_typed_data(&addr, &tampered, &sig));
            let _ = canonical;
        }
    }

    #[test]
    fn typed_data_domain_differs_from_message_domain() {
        // A message signature is never valid as a typed-data signature and back,
        // even over identical bytes: the domain tags separate the preimages.
        let key = WalletSigningKey::ed25519([0x42u8; 32]);
        let addr = key.address();
        let msg_sig = key.sign_message(CHAIN_MAIN, b"transfer").expect("signs");
        let data = TypedCallData::new(
            &[0u8; 32],
            "m",
            serde_json::json!("transfer"),
            0,
            0,
            CHAIN_MAIN,
        )
        .expect("builds");
        assert!(!verify_typed_data(&addr, &data, &msg_sig));
        let (typed_sig, _) = key.sign_typed_data(&data).expect("signs");
        let canonical = canonical_typed_data_json(&data);
        assert!(!verify_message(
            &addr,
            CHAIN_MAIN,
            canonical.as_bytes(),
            &typed_sig
        ));
    }

    #[test]
    fn oversized_inputs_are_refused() {
        let key = WalletSigningKey::ed25519([0x42u8; 32]);
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        assert!(key.sign_message(CHAIN_MAIN, &big).is_err());
        assert!(parse_message_param(Some(&"x".repeat(MAX_MESSAGE_BYTES + 1)), None).is_err());
        assert!(
            TypedCallData::new(&[0u8; 32], "", serde_json::json!(null), 0, 0, CHAIN_MAIN).is_err()
        );
        assert!(TypedCallData::new(
            &[0u8; 32],
            &"m".repeat(MAX_METHOD_BYTES + 1),
            serde_json::json!(null),
            0,
            0,
            CHAIN_MAIN
        )
        .is_err());
    }

    #[test]
    fn test_vector_ed25519() {
        // Pinned vector, also published in docs/WALLET_SIGNING.md.
        // seed = 0x42*32, chain = 5757, message = "hello stellereum".
        let key = WalletSigningKey::ed25519([0x42u8; 32]);
        let addr = key.address();
        assert_eq!(
            hex::encode(addr),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        );
        let sig = key.sign_message(5757, b"hello stellereum").expect("signs");
        let hex_sig = sig.to_hex();
        assert_eq!(
            hex_sig,
            "010100202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120040a8ebb8d6b79fcd9c5937fa53789ba4b138c56e7ce1d8356817a1d4ae03c0fc4e5d24e630b106ce5591cd948b1e059d29caf495181c9deeb081685938c83d8e0d"
        );
        assert!(verify_message(&addr, 5757, b"hello stellereum", &sig));
        // Re-decodes and still verifies (the doc vector is this exact string).
        let back = WalletSignature::from_hex(&hex_sig).expect("decodes");
        assert_eq!(back, sig);
        println!("ED25519_VECTOR sig={hex_sig}");
    }

    #[test]
    fn test_vector_addresses_and_preimage() {
        // Pinned vectors, also published in docs/WALLET_SIGNING.md.
        // Falcon/Hybrid signatures are RANDOMIZED (FIPS 206 sampler), so only
        // the addresses and the preimage are pinned — never a signature.
        let falcon = WalletSigningKey::falcon_from_seed(&[0x77u8; 32]);
        let hybrid = WalletSigningKey::hybrid([0x42u8; 32], &[0x77u8; 32]);
        assert_eq!(
            hex::encode(falcon.address()),
            "549f119ff1a76b7ce82cc87bc86b130db8136f189068209dcbf9b00ef7125cd5"
        );
        assert_eq!(
            hex::encode(hybrid.address()),
            "84cb0826fa62b1953b06befa2bfe602b4ea10f2d76672242796147ae7d94fbed"
        );
        let pre = message_preimage(5757, b"hello stellereum");
        println!("PREIMAGE {}", hex::encode(&pre));
        assert_eq!(
            hex::encode(&pre),
            "5374656c6c657265756d205369676e6564204d6573736167653a0a5354454c4c2d4d53475349472d5631000000000000167d000000000000001068656c6c6f207374656c6c657265756d"
        );
    }
}
