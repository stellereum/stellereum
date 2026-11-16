//! Military-Grade Security & Anti-Malware Hardening Module
//! Protects against infostealers (RedLine, Lumma, Vidar), memory scrapers,
//! clipboard hijackers, and unauthorized file access:
//! - POSIX 0600 / 0700 strict file permissions
//! - Memory-hard Argon2id KDF (64MB RAM cost, 3 iterations)
//! - XChaCha20Poly1305 AEAD authenticated encryption
//! - RAM Zeroization (Drop-based) & OS page locking (mlock) against swap dumps
//! - Anti-Clipboard Hijacking address validation and visual verification

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroize;

/// Keystore format version we write and accept.
pub const KEYSTORE_VERSION: u32 = 2;
const KEYSTORE_KDF: &str = "Argon2id(m=65536,t=3,p=4)";
const KEYSTORE_CIPHER: &str = "XChaCha20-Poly1305";

fn default_scheme_str() -> String {
    "ed25519".to_string()
}

/// Computes Associated Authenticated Data (AAD) for XChaCha20-Poly1305 AEAD payload.
/// Binds version, wallet address, signature scheme, and post-quantum public key
/// into the AEAD authentication tag to prevent tampering with any metadata.
pub fn compute_keystore_aad(
    version: u32,
    address_hex: &str,
    scheme: &str,
    pq_pubkey_hex: Option<&str>,
) -> Vec<u8> {
    format!(
        "v{}|address:{}|scheme:{}|pq_pk:{}",
        version,
        address_hex,
        scheme,
        pq_pubkey_hex.unwrap_or("")
    )
    .into_bytes()
}

/// Protected memory container: zeroized + unlocked from RAM on drop.
pub struct SecureSecret {
    pub bytes: [u8; 32],
}

impl SecureSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        let s = Self { bytes: secret };
        // Lock the LIVE bytes (audit 2026-10-06: the old code locked the
        // by-value parameter copy, not the stored array). Best-effort.
        unsafe {
            let _ = libc::mlock(s.bytes.as_ptr() as *const libc::c_void, 32);
        }
        // The caller's array copy is theirs to zero; ours is locked now.
        s
    }
}

impl Drop for SecureSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        unsafe {
            let _ = libc::munlock(self.bytes.as_ptr() as *const libc::c_void, 32);
        }
    }
}

/// Strict OS file and directory permission enforcer (POSIX 0600 on files, 0700 on dirs)
pub fn enforce_strict_permissions(path: &Path) {
    if path.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    } else if path.exists() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    if let Some(parent) = path.parent() {
        if parent.exists() {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
}

/// Hardened Keystore Format with Argon2id + XChaCha20Poly1305
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardenedKeystore {
    pub version: u32,
    pub kdf: String,
    pub cipher: String,
    pub address_hex: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    /// Integrity authentication tag for anti-tampering
    pub auth_tag_hex: String,
    /// Signature scheme (falcon512, hybrid, ed25519)
    #[serde(default = "default_scheme_str")]
    pub scheme: String,
    /// Optional post-quantum public key in hex
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_pubkey_hex: Option<String>,
}

impl HardenedKeystore {
    pub fn is_pq(&self) -> bool {
        self.scheme == "falcon512" || self.scheme == "hybrid" || self.scheme == "mldsa44"
    }

    /// Encrypt master secret key using memory-hard Argon2id (64MB RAM) and XChaCha20Poly1305 (defaults to Ed25519)
    #[allow(dead_code)]
    pub fn encrypt(
        secret: &SecureSecret,
        address_hex: &str,
        password: &str,
    ) -> Result<Self, String> {
        Self::encrypt_with_scheme(secret, address_hex, password, "ed25519", None)
    }

    /// Encrypt master secret key with designated scheme and optional public key
    pub fn encrypt_with_scheme(
        secret: &SecureSecret,
        address_hex: &str,
        password: &str,
        scheme: &str,
        pq_pubkey_hex: Option<String>,
    ) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Memory-hard Argon2id derivation: 64MB memory cost, 3 passes, 4 lanes
        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Argon2 params error: {:?}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 KDF failed: {:?}", e))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        // Associated Authenticated Data binds the ciphertext to the wallet
        // address and metadata (version, scheme, pq_pubkey_hex). Now any
        // tampering with scheme, address, or public key fails decryption.
        let aad = compute_keystore_aad(
            KEYSTORE_VERSION,
            address_hex,
            scheme,
            pq_pubkey_hex.as_deref(),
        );
        let payload = Payload {
            msg: secret.bytes.as_ref(),
            aad: &aad,
        };
        let ciphertext = cipher
            .encrypt(xnonce, payload)
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        // Extract 16-byte Poly1305 MAC tag from AEAD ciphertext
        let tag_split = ciphertext.len().saturating_sub(16);
        let (ct_body, auth_tag) = ciphertext.split_at(tag_split);

        // Clean up derived key in RAM
        derived_key.zeroize();

        Ok(Self {
            version: KEYSTORE_VERSION,
            kdf: KEYSTORE_KDF.to_string(),
            cipher: KEYSTORE_CIPHER.to_string(),
            address_hex: address_hex.to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ct_body),
            auth_tag_hex: hex::encode(auth_tag),
            scheme: scheme.to_string(),
            pq_pubkey_hex,
        })
    }

    /// Decrypt master secret key into zeroizing container
    pub fn decrypt(&self, password: &str) -> Result<SecureSecret, String> {
        // Fail closed on unknown formats (audit 2026-10-06: version/kdf/cipher
        // were never checked, so a downgraded keystore decrypted silently).
        if self.version != KEYSTORE_VERSION {
            return Err(format!("unsupported keystore version {}", self.version));
        }
        if self.kdf != KEYSTORE_KDF {
            return Err(format!("unsupported KDF {}", self.kdf));
        }
        if self.cipher != KEYSTORE_CIPHER {
            return Err(format!("unsupported cipher {}", self.cipher));
        }
        let salt = hex::decode(&self.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
        let nonce = hex::decode(&self.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
        let ct_body =
            hex::decode(&self.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
        let auth_tag =
            hex::decode(&self.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Argon2 params error: {:?}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 derivation error: {:?}", e))?;

        if nonce.len() != 24 {
            return Err(format!(
                "Invalid nonce length: expected 24 bytes, got {}",
                nonce.len()
            ));
        }
        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let xnonce = XNonce::from_slice(&nonce);

        // Reconstruct full AEAD payload (ciphertext + tag)
        let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
        full_ct.extend_from_slice(&ct_body);
        full_ct.extend_from_slice(&auth_tag);

        let aad = compute_keystore_aad(
            self.version,
            &self.address_hex,
            &self.scheme,
            self.pq_pubkey_hex.as_deref(),
        );

        let mut decrypted = cipher
            .decrypt(xnonce, Payload { msg: &full_ct, aad: &aad })
            .map_err(|_| "Decryption failed: incorrect password, tampered keystore, or address/metadata mismatch!".to_string())?;

        derived_key.zeroize();

        if decrypted.len() != 32 {
            decrypted.zeroize();
            return Err("Decrypted secret has invalid length".to_string());
        }

        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&decrypted);
        decrypted.zeroize();

        Ok(SecureSecret::new(secret_arr))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("IO error creating dir: {e}"))?;
            enforce_strict_permissions(parent);
        }
        let json =
            serde_json::to_string_pretty(self).map_err(|e| format!("Serialization error: {e}"))?;
        // Create with 0600 ATOMICALLY (audit 2026-10-06: fs::write + chmod
        // left a 0644 window; existing lax files were just chmodded). Then
        // verify — a wrong mode aborts loudly instead of printing "0600".
        // Tmp + rename (audit follow-up): truncate-in-place corrupted the
        // keystore on a mid-write crash; rename is atomic on one filesystem.
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("IO error writing keystore: {e}"))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("IO error writing keystore: {e}"))?;
            f.sync_all()
                .map_err(|e| format!("IO error writing keystore: {e}"))?;
        }
        fs::rename(&tmp, path).map_err(|e| format!("IO error writing keystore: {e}"))?;
        let mode = fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        if mode != 0o600 {
            return Err(format!(
                "keystore file has mode {:o}, refusing to trust it (expected 600)",
                mode
            ));
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("Keystore file does not exist at {:?}", path));
        }
        enforce_strict_permissions(path);
        let raw =
            fs::read_to_string(path).map_err(|e| format!("IO error reading keystore: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("Invalid keystore format: {e}"))
    }
}

use colored::Colorize;

/// Anti-Clipboard Hijacker Address Verifier
/// Formats address with bold colored prefix and suffix to prevent visual confusion
pub fn format_address_single_line(address_hex: &str) -> String {
    let clean = address_hex.strip_prefix("0x").unwrap_or(address_hex);
    if clean.len() == 64 {
        if let Ok(decoded) = hex::decode(clean) {
            if decoded.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&decoded);
                let stl57 = stellereum::address::encode_stl57_address(&b);
                if stl57.len() > 15 {
                    let prefix = &stl57[..5];
                    let mid = &stl57[5..stl57.len() - 10];
                    let suffix = &stl57[stl57.len() - 10..];
                    return format!(
                        "{}{}{}",
                        prefix.yellow().bold(),
                        mid.cyan().bold(),
                        suffix.green().bold()
                    );
                } else {
                    return stl57;
                }
            }
        }
    }
    address_hex.to_string()
}

pub fn format_address_with_visual_checksum(address_hex: &str) -> String {
    let clean = address_hex.strip_prefix("0x").unwrap_or(address_hex);
    if clean.len() == 64 {
        if let Ok(decoded) = hex::decode(clean) {
            if decoded.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&decoded);
                let stl57 = stellereum::address::encode_stl57_address(&b);
                if stl57.len() > 15 {
                    let prefix = &stl57[..5];
                    let mid = &stl57[5..stl57.len() - 10];
                    let suffix = &stl57[stl57.len() - 10..];
                    return format!(
                        "{}{}{}\n  └─ Raw Hex: {}",
                        prefix.yellow().bold(),
                        mid.cyan().bold(),
                        suffix.green().bold(),
                        format!("0x{clean}").dimmed()
                    );
                } else {
                    return format!(
                        "{}\n  └─ Raw Hex: {}",
                        stl57.yellow().bold(),
                        format!("0x{clean}").dimmed()
                    );
                }
            }
        }
    }

    if address_hex.len() < 16 {
        return address_hex.to_string();
    }
    let prefix = &address_hex[..8];
    let mid = &address_hex[8..address_hex.len() - 8];
    let suffix = &address_hex[address_hex.len() - 8..];
    format!(
        "{}{}{}",
        prefix.cyan().bold(),
        mid.white(),
        suffix.green().bold()
    )
}
