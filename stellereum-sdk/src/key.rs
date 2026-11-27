//! Falcon-512 key material, addresses and signing.
//!
//! # Why this does not use `stellereum::post_quantum::FalconKeypair`
//!
//! The node's `FalconKeypair` lives inside the node crate. Depending on that
//! crate from a wallet would pull the whole consensus node (tokio, axum,
//! sled, wasmi, the RPC state, ...) into the client binary. The Falcon-512
//! primitive itself is standard FIPS 206, so this module uses the PQClean
//! `falcon-padded-512` implementation (`pqcrypto-falcon`) directly.
//!
//! The node's canonical wire byte is the padded 666-byte signature with
//! header `0x29` (`stellereum/src/post_quantum.rs:2179`); PQClean emits the
//! same math with header `0x39`. [`FalconKeypair::sign`] normalises the
//! header to the chain's byte and [`FalconKeypair::verify`] normalises it
//! back for the local check. The parity test
//! `tests/parity.rs::signature_verifies_with_node_verify_pq_signature`
//! proves the node's own verifier accepts the result.

//! # Key format
//!
//! The SDK key file stores the PQClean Falcon-512 material: the 897-byte
//! public key and the 1281-byte secret key `(f, g, F)`. The node operator's
//! `FalconKeypair::to_bytes` container
//! (`stellereum/src/post_quantum.rs:1741-1870`) is a different, expanded
//! polynomial layout and is NOT importable here; public keys and signatures
//! are interoperable, the private-key container is not. Generate an SDK key
//! for wallet use.

use pqcrypto_falcon::falconpadded512::{
    detached_sign, keypair, verify_detached_signature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::address;
use crate::error::{Result, SdkError};

/// Falcon-512 public key size in bytes (FIPS 206 encoding, header `0x09`).
pub const FALCON512_PUBKEY_LEN: usize = 897;
/// Falcon-512 padded signature size in bytes (chain-canonical header `0x29`).
pub const FALCON512_SIG_LEN: usize = 666;
/// `PqScheme::Falcon512 as u8` in the node
/// (`stellereum/src/post_quantum.rs:154`).
pub const PQ_SCHEME_FALCON512: u8 = 2;
/// Default 16-byte address salt (`stellereum/src/post_quantum.rs:129`).
pub const DEFAULT_SALT: [u8; 16] = [0u8; 16];
/// Address derivation domain (`stellereum/src/post_quantum.rs:121`).
pub const PQ_ADDRESS_DOMAIN: &[u8] = b"STL_ADDR_V4";
/// Chain-canonical signature header (`stellereum/src/post_quantum.rs:2179`).
pub const CHAIN_SIG_HEADER: u8 = 0x29;
/// PQClean's header for the same math (see the module docs).
pub const PQCLEAN_SIG_HEADER: u8 = 0x39;

/// The 32-byte address of a Falcon-512 public key, using the same domain
/// separation and zero salt as the node:
/// `BLAKE3("STL_ADDR_V4" || 0x02 || pubkey || salt)`.
pub fn derive_pq_address(pubkey: &[u8], salt: &[u8; 16]) -> Result<[u8; 32]> {
    if pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(SdkError::InvalidKey(format!(
            "Falcon-512 public key must be {FALCON512_PUBKEY_LEN} bytes, got {}",
            pubkey.len()
        )));
    }
    let mut h = blake3::Hasher::new();
    h.update(PQ_ADDRESS_DOMAIN);
    h.update(&[PQ_SCHEME_FALCON512]);
    h.update(pubkey);
    h.update(salt);
    Ok(*h.finalize().as_bytes())
}

/// Verify a chain-canonical Falcon-512 signature against a raw public key.
///
/// This is a free function so callers that only have public material (for
/// example a session grant's `master_pubkey`) can verify without constructing
/// a [`FalconKeypair`].
pub fn verify_pq_signature(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != FALCON512_PUBKEY_LEN || signature.len() != FALCON512_SIG_LEN {
        return false;
    }
    let Ok(pk) = PublicKey::from_bytes(pubkey) else {
        return false;
    };
    let mut local = signature.to_vec();
    local[0] = PQCLEAN_SIG_HEADER;
    let Ok(sig) = pqcrypto_falcon::falconpadded512::DetachedSignature::from_bytes(&local) else {
        return false;
    };
    verify_detached_signature(&sig, message, &pk).is_ok()
}

/// A Falcon-512 keypair owned by the client.
///
/// The secret key is held in a [`Zeroizing`] buffer and is never printed by
/// [`Debug`]. Export it only through [`FalconKeypair::to_key_file`], which
/// makes the plaintext nature explicit.
pub struct FalconKeypair {
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for FalconKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FalconKeypair")
            .field("public_key", &hex::encode(&self.public_key))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for FalconKeypair {
    fn clone(&self) -> Self {
        // `Zeroizing<Vec<u8>>` implements Clone; the copy is zeroized on drop.
        Self {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
        }
    }
}

impl FalconKeypair {
    /// Generate a fresh keypair from OS entropy.
    pub fn generate() -> Result<Self> {
        let (pk, sk) = keypair();
        Self::from_parts(pk.as_bytes(), sk.as_bytes())
    }

    fn from_parts(public: &[u8], secret: &[u8]) -> Result<Self> {
        if public.len() != FALCON512_PUBKEY_LEN {
            return Err(SdkError::InvalidKey(format!(
                "public key must be {FALCON512_PUBKEY_LEN} bytes, got {}",
                public.len()
            )));
        }
        if public.first() != Some(&0x09) {
            return Err(SdkError::InvalidKey(
                "public key does not carry the FIPS 206 0x09 header".into(),
            ));
        }
        SecretKey::from_bytes(secret)
            .map_err(|e| SdkError::InvalidKey(format!("secret key: {e}")))
            .and_then(|_| {
                // PQClean re-derives the public key from the secret key on
                // every sign; verify the caller's pair is consistent by
                // signing a probe and checking it against the public key.
                let probe = Self {
                    public_key: public.to_vec(),
                    secret_key: Zeroizing::new(secret.to_vec()),
                };
                let msg = b"stellereum-sdk key consistency probe";
                let sig = probe
                    .sign(msg)
                    .map_err(|e| SdkError::InvalidKey(format!("key pair mismatch: {e}")))?;
                if !probe.verify(msg, &sig) {
                    return Err(SdkError::InvalidKey(
                        "secret key does not match the public key".into(),
                    ));
                }
                Ok(())
            })?;
        Ok(Self {
            public_key: public.to_vec(),
            secret_key: Zeroizing::new(secret.to_vec()),
        })
    }

    /// Load a keypair from explicit public and secret bytes.
    ///
    /// PQClean's Falcon-512 secret key encodes only `(f, g, F)`; it does not
    /// embed the public key, so both halves are required. The SDK's JSON key
    /// file stores both (and the address commits to the public half).
    pub fn from_public_and_secret(public: &[u8], secret: &[u8]) -> Result<Self> {
        Self::from_parts(public, secret)
    }

    /// Canonical 897-byte public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Secret-key bytes. Handle with care; the buffer returned is a copy.
    ///
    /// Prefer [`FalconKeypair::secret_key_bytes_zeroizing`] when the caller can
    /// hold a [`Zeroizing`] wrapper so the copy is scrubbed on drop.
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_vec()
    }

    /// Secret-key bytes wrapped in [`Zeroizing`] so the copy is scrubbed on drop.
    pub fn secret_key_bytes_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        self.secret_key.clone()
    }

    /// Lower-case hex public key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// Lower-case hex secret key (plaintext; export only to a protected file).
    ///
    /// Prefer [`FalconKeypair::secret_key_hex_zeroizing`] when the caller can
    /// hold a [`Zeroizing`] wrapper so the hex copy is scrubbed on drop.
    pub fn secret_key_hex(&self) -> String {
        hex::encode(&*self.secret_key)
    }

    /// Lower-case hex secret key wrapped in [`Zeroizing`] so the hex copy is
    /// scrubbed on drop.
    pub fn secret_key_hex_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(&*self.secret_key))
    }

    /// The 32-byte Stellereum address (`derive_pq_address` with the zero salt).
    pub fn address(&self) -> [u8; 32] {
        derive_pq_address(&self.public_key, &DEFAULT_SALT)
            .expect("a FalconKeypair always carries a 897-byte public key")
    }

    /// Lower-case hex address.
    pub fn address_hex(&self) -> String {
        address::to_hex(&self.address())
    }

    /// Branded `Stl57...` address.
    pub fn address_stl57(&self) -> String {
        address::encode_stl57(&self.address())
    }

    /// Sign `message` and return the chain-canonical 666-byte padded
    /// signature (header `0x29`, zero padded to the fixed length).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| SdkError::SigningFailed(format!("secret key: {e}")))?;
        let pk = PublicKey::from_bytes(&self.public_key)
            .map_err(|e| SdkError::SigningFailed(format!("public key: {e}")))?;
        let mut sig = detached_sign(message, &sk).as_bytes().to_vec();
        if sig.len() != FALCON512_SIG_LEN {
            return Err(SdkError::SigningFailed(format!(
                "Falcon-512 produced {} signature bytes, expected {FALCON512_SIG_LEN}",
                sig.len()
            )));
        }
        if sig[0] == PQCLEAN_SIG_HEADER {
            sig[0] = CHAIN_SIG_HEADER;
        } else if sig[0] != CHAIN_SIG_HEADER {
            return Err(SdkError::SigningFailed(format!(
                "unexpected Falcon signature header 0x{:02x}",
                sig[0]
            )));
        }
        // Fail closed: never hand back a signature this key cannot verify.
        let mut local = sig.clone();
        local[0] = PQCLEAN_SIG_HEADER;
        let local_sig = pqcrypto_falcon::falconpadded512::DetachedSignature::from_bytes(&local)
            .map_err(|e| SdkError::SigningFailed(format!("signature framing: {e}")))?;
        verify_detached_signature(&local_sig, message, &pk)
            .map_err(|e| SdkError::SigningFailed(format!("self-check failed: {e}")))?;
        Ok(sig)
    }

    /// Verify a chain-canonical signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != FALCON512_SIG_LEN {
            return false;
        }
        let Ok(pk) = PublicKey::from_bytes(&self.public_key) else {
            return false;
        };
        let mut local = signature.to_vec();
        local[0] = PQCLEAN_SIG_HEADER;
        let Ok(sig) = pqcrypto_falcon::falconpadded512::DetachedSignature::from_bytes(&local)
        else {
            return false;
        };
        verify_detached_signature(&sig, message, &pk).is_ok()
    }

    /// Export a versioned JSON key file.
    pub fn to_key_file(&self) -> KeyFile {
        KeyFile {
            version: 1,
            scheme: "falcon512".into(),
            address: self.address_stl57(),
            public_key: self.public_key_hex(),
            secret_key: self.secret_key_hex(),
            label: None,
        }
    }

    /// Load from a JSON key file, validating that the address commits to the
    /// stored public key.
    pub fn from_key_file(file: &KeyFile) -> Result<Self> {
        if file.version != 1 {
            return Err(SdkError::InvalidKey(format!(
                "unsupported key file version {}",
                file.version
            )));
        }
        if !file.scheme.eq_ignore_ascii_case("falcon512") {
            return Err(SdkError::InvalidKey(format!(
                "unsupported scheme {:?}; only Falcon-512 is live",
                file.scheme
            )));
        }
        let pk = hex::decode(&file.public_key)
            .map_err(|e| SdkError::InvalidKey(format!("public_key hex: {e}")))?;
        let sk = Zeroizing::new(
            hex::decode(&file.secret_key)
                .map_err(|e| SdkError::InvalidKey(format!("secret_key hex: {e}")))?,
        );
        let kp = Self::from_parts(&pk, &sk)?;
        if !file.address.trim().is_empty() {
            let expected = address::parse_address(&file.address)?;
            if expected != kp.address() {
                return Err(SdkError::InvalidKey(
                    "key file address does not derive from its public key".into(),
                ));
            }
        }
        Ok(kp)
    }

    /// Write a JSON key file. The file is created with mode 0600 on Unix.
    pub fn save_key_file(&self, path: &std::path::Path) -> Result<()> {
        let key_file = self.to_key_file();
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(&key_file)
                .map_err(|e| SdkError::InvalidKey(format!("serialize key file: {e}")))?,
        );
        write_private(path, &json)
            .map_err(|e| SdkError::InvalidKey(format!("write {}: {e}", path.display())))
    }

    /// Read a JSON key file.
    pub fn load_key_file(path: &std::path::Path) -> Result<Self> {
        let raw = Zeroizing::new(
            std::fs::read(path)
                .map_err(|e| SdkError::InvalidKey(format!("read {}: {e}", path.display())))?,
        );
        let file: KeyFile = serde_json::from_slice(&raw)
            .map_err(|e| SdkError::InvalidKey(format!("parse {}: {e}", path.display())))?;
        Self::from_key_file(&file)
    }
}

impl Drop for FalconKeypair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.public_key.zeroize();
    }
}

/// Versioned, plaintext-on-disk key file.
///
/// There is no password/KDF here on purpose: the SDK ships no authenticated
/// encryption dependency. Keep the file at mode 0600 (the writer does) or
/// wrap it in the OS keystore; `docs/SDK.md` says this plainly.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyFile {
    pub version: u8,
    pub scheme: String,
    pub address: String,
    pub public_key: String,
    pub secret_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Zeroize for KeyFile {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for KeyFile {}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("version", &self.version)
            .field("scheme", &self.scheme)
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .field("label", &self.label)
            .finish()
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `OpenOptionsExt::mode` applies ONLY when the file is created. An
        // existing file (a re-export, or a path a previous version wrote with
        // the process umask) would otherwise be truncated and rewritten with
        // the SECRET KEY while keeping its old, possibly world-readable mode.
        // Tighten it explicitly before a single secret byte is written.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify_address() {
        let kp = FalconKeypair::generate().unwrap();
        assert_eq!(kp.public_key().len(), FALCON512_PUBKEY_LEN);
        let sig = kp.sign(b"hello").unwrap();
        assert_eq!(sig.len(), FALCON512_SIG_LEN);
        assert_eq!(sig[0], CHAIN_SIG_HEADER);
        assert!(kp.verify(b"hello", &sig));
        assert!(!kp.verify(b"hell0", &sig));
        assert_ne!(kp.address(), [0u8; 32]);
    }

    #[test]
    fn keyfile_roundtrip() {
        let kp = FalconKeypair::generate().unwrap();
        let file = kp.to_key_file();
        let back = FalconKeypair::from_key_file(&file).unwrap();
        assert_eq!(back.public_key(), kp.public_key());
        assert_eq!(back.address(), kp.address());
    }

    #[test]
    fn secret_key_must_be_paired_with_its_public_key() {
        let a = FalconKeypair::generate().unwrap();
        let b = FalconKeypair::generate().unwrap();
        assert!(
            FalconKeypair::from_public_and_secret(a.public_key(), &b.secret_key_bytes()).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn r2x_save_key_file_tightens_an_existing_permissive_file() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "stell-sdk-r2x-keyfile-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("key.json");

        // A pre-existing, world-readable file at the destination (the bug:
        // save_key_file truncated it and left 0o644 on the secret).
        std::fs::write(&path, b"stale").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let kp = FalconKeypair::generate().unwrap();
        kp.save_key_file(&path).expect("save");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "rewriting an existing key file must tighten it to 0600 (got {mode:o})"
        );
        assert_eq!(
            FalconKeypair::load_key_file(&path).expect("load").address(),
            kp.address()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyfile_zeroizes_secret_key_and_zeroizing_variants_match() {
        fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<KeyFile>();

        let kp = FalconKeypair::generate().unwrap();
        assert_eq!(*kp.secret_key_bytes_zeroizing(), kp.secret_key_bytes());
        assert_eq!(*kp.secret_key_hex_zeroizing(), kp.secret_key_hex());

        let mut file = kp.to_key_file();
        assert!(!file.secret_key.is_empty());
        file.zeroize();
        assert!(file.secret_key.is_empty());
        assert!(!file.public_key.is_empty());
    }
}
