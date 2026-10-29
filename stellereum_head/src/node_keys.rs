//! Node key security hardening: Argon2id + XChaCha20-Poly1305 encryption
//! and strict file/directory permission enforcement (0600 / 0700).

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const ENV_PASSPHRASE: &str = "STELL_NODE_PASSPHRASE";
pub const FALLBACK_ENV_PASSPHRASE: &str = "INFNODE_KEY_PASSPHRASE";

const KDF_MEM_KIB: u32 = 65_536;
const KDF_ITERS: u32 = 3;
const KDF_LANES: u32 = 4;

/// Resolve passphrase from `STELL_NODE_PASSPHRASE`, falling back to `INFNODE_KEY_PASSPHRASE`.
///
/// SECRET HYGIENE: the returned `String` holds key material on the heap.
/// Callers MUST wrap it in [`Zeroizing`] immediately and never log, print,
/// or include it in errors (all load/save paths below do this).
pub fn get_passphrase() -> Option<String> {
    std::env::var(ENV_PASSPHRASE)
        .ok()
        .or_else(|| std::env::var(FALLBACK_ENV_PASSPHRASE).ok())
        .filter(|p| !p.is_empty())
}

/// Derive a 32-byte symmetric key from a passphrase and salt using Argon2id.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(KDF_MEM_KIB, KDF_ITERS, KDF_LANES, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!("argon2 kdf: {e}"))?;
    Ok(*key)
}

/// Verify that directory exists and on Unix has strict 0700 permissions.
pub fn verify_dir_perms(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir)
            .map_err(|e| anyhow!("keystore directory {}: {e}", dir.display()))?;
        if !meta.is_dir() {
            bail!("path {} is not a directory", dir.display());
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            bail!(
                "keystore directory {} has insecure permissions 0o{:03o}, expected 0o700 (owner-only)",
                dir.display(),
                mode
            );
        }
    }
    #[cfg(not(unix))]
    {
        if !dir.is_dir() {
            bail!("path {} is not a directory", dir.display());
        }
    }
    Ok(())
}

/// Verify that file exists and on Unix has strict 0600 permissions.
pub fn verify_file_perms(file: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(file)
            .map_err(|e| anyhow!("key file {}: {e}", file.display()))?;
        if !meta.is_file() {
            bail!("key path {} is not a file", file.display());
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "key file {} has insecure permissions 0o{:03o}, expected 0o600 (owner-only)",
                file.display(),
                mode
            );
        }
    }
    #[cfg(not(unix))]
    {
        if !file.is_file() {
            bail!("key path {} is not a file", file.display());
        }
    }
    Ok(())
}

/// Ensure directory exists with 0700 permissions.
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write private file with 0600 permissions.
///
/// On Unix the file is created with mode 0600 AND re-chmodded to 0600 after
/// the write, so a PRE-EXISTING file with lax permissions is tightened rather
/// than left world-readable (creation mode alone only applies to new files).
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents)?;
        drop(f);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// Encrypt raw bytes with Argon2id + XChaCha20-Poly1305 using passphrase.
/// Output format: `enc2:<salt_hex>:<nonce_hex>:<ct_hex>`.
pub fn encrypt_bytes(data: &[u8], passphrase: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = Zeroizing::new(derive_key(passphrase, &salt)?);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), data)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    key.zeroize();
    Ok(format!(
        "enc2:{}:{}:{}",
        hex::encode(salt),
        hex::encode(nonce),
        hex::encode(&ct)
    ))
}

/// Decrypt bytes. Supports `enc2:` (Argon2id + XChaCha20-Poly1305), legacy `enc:`, and plaintext fallback.
pub fn decrypt_bytes(raw: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok();
    if let Some(s) = text {
        let s_trimmed = s.trim();
        if let Some(rest) = s_trimmed.strip_prefix("enc2:") {
            let pass = passphrase.ok_or_else(|| {
                anyhow!("key is encrypted with Argon2id, but STELL_NODE_PASSPHRASE is not set")
            })?;
            let parts: Vec<&str> = rest.splitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("bad enc2 blob");
            }
            let salt = hex::decode(parts[0]).map_err(|e| anyhow!("invalid salt hex: {e}"))?;
            let nonce = hex::decode(parts[1]).map_err(|e| anyhow!("invalid nonce hex: {e}"))?;
            let ct = hex::decode(parts[2]).map_err(|e| anyhow!("invalid ciphertext hex: {e}"))?;
            let mut key = Zeroizing::new(derive_key(pass, &salt)?);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
            let plain = cipher
                .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
                .map_err(|_| anyhow!("invalid passphrase for node key"))?;
            key.zeroize();
            return Ok(plain);
        } else if s_trimmed.starts_with("enc:") {
            let _pass = passphrase.ok_or_else(|| {
                anyhow!("key is encrypted, but STELL_NODE_PASSPHRASE is not set")
            })?;
            // Legacy `enc:` blobs delegate to `infnode::keyring::unprotect`,
            // whose KDF is 65536x iteration of UNSALTED blake3 (no salt, weak
            // passphrase hashing) — outside this audit's reach. DEPRECATED:
            // re-save through `encrypt_bytes` (enc2: Argon2id 64MiB/3/4 +
            // random salt) at the next passphrase rotation. See operator item.
            let plain_str = infnode::keyring::unprotect(s_trimmed)
                .map_err(|e| anyhow!("invalid legacy enc blob: {e}"))?;
            return Ok(plain_str.into_bytes());
        }
    }

    // Plaintext fallback
    if passphrase.is_none() {
        tracing::warn!("STELL_NODE_PASSPHRASE is not set: node key loaded in plaintext!");
        eprintln!("[WARN] STELL_NODE_PASSPHRASE is not set: node key loaded in plaintext!");
    } else {
        tracing::warn!("STELL_NODE_PASSPHRASE is set, but key was stored in plaintext on disk");
    }
    Ok(raw.to_vec())
}

/// Load Falcon-512 keypair from path, verifying permissions and decrypting if encrypted.
pub fn load_falcon_key(path: &Path) -> Result<crate::post_quantum::FalconKeypair> {
    if let Some(parent) = path.parent() {
        if parent.exists() {
            verify_dir_perms(parent)?;
        }
    }
    verify_file_perms(path)?;
    let raw = std::fs::read(path).map_err(|e| anyhow!("read falcon key {}: {e}", path.display()))?;
    let pass = Zeroizing::new(get_passphrase());
    let plain_bytes = Zeroizing::new(decrypt_bytes(&raw, pass.as_deref())?);
    crate::post_quantum::FalconKeypair::from_bytes(&plain_bytes)
        .ok_or_else(|| anyhow!("invalid Falcon-512 key in {}", path.display()))
}

/// Save Falcon-512 keypair to path with strict permissions (0600 file, 0700 dir),
/// encrypting with Argon2id + XChaCha20-Poly1305 if STELL_NODE_PASSPHRASE is set.
pub fn save_falcon_key(path: &Path, key: &crate::post_quantum::FalconKeypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_secure_dir(parent)?;
    }
    let key_bytes = Zeroizing::new(key.to_bytes());
    let pass = Zeroizing::new(get_passphrase());
    let content = if let Some(p) = pass.as_deref() {
        Zeroizing::new(encrypt_bytes(&key_bytes, p)?.into_bytes())
    } else {
        tracing::warn!("STELL_NODE_PASSPHRASE is not set: saving falcon.key in plaintext!");
        eprintln!("[WARN] STELL_NODE_PASSPHRASE is not set: saving falcon.key in plaintext!");
        key_bytes.clone()
    };
    write_private_file(path, &content)
}

/// Load or generate and save Falcon-512 keypair.
pub fn load_or_generate_falcon_key(path: &Path) -> Result<crate::post_quantum::FalconKeypair> {
    if path.exists() {
        load_falcon_key(path)
    } else {
        let k = crate::post_quantum::FalconKeypair::generate();
        save_falcon_key(path, &k)?;
        Ok(k)
    }
}

/// Load infnode NodeKeys (identity.key and e2e.key) with strict permission checks and decryption.
///
/// OPERATIONAL (audit open risk #4): the returned `NodeKeys` (an `infnode`
/// type with NO `Zeroize` bound — outside this module's reach) holds the
/// Ed25519 identity seed and the x25519 e2e secret in process heap. There is
/// no PFS claim on the e2e channel: a heap disclosure (core dump, swap,
/// `/proc/<pid>/mem`) exposes both long-term secrets. Operators MUST disable
/// core dumps and encrypted-swap-or-no-swap on validators; treat the e2e
/// secret as long-lived (no forward secrecy) in the threat model. What this
/// function DOES guarantee: 0700/0600 enforcement fail-closed, Argon2id
/// decryption with wrong-passphrase rejection, and `Zeroizing` for every
/// transient buffer up to the (un-wipeable) return value.
pub fn load_node_keys(dir: &Path) -> Result<infnode::keyring::NodeKeys> {
    verify_dir_perms(dir)?;
    let id_path = dir.join("identity.key");
    let e2e_path = dir.join("e2e.key");
    verify_file_perms(&id_path)?;
    verify_file_perms(&e2e_path)?;

    let id_raw = std::fs::read(&id_path).map_err(|e| anyhow!("identity.key: {e}"))?;
    let e2e_raw = std::fs::read(&e2e_path).map_err(|e| anyhow!("e2e.key: {e}"))?;

    let pass = Zeroizing::new(get_passphrase());
    let id_plain = Zeroizing::new(decrypt_bytes(&id_raw, pass.as_deref())?);
    let e2e_plain = Zeroizing::new(decrypt_bytes(&e2e_raw, pass.as_deref())?);

    let id_str = std::str::from_utf8(&id_plain)?.trim();
    let e2e_str = std::str::from_utf8(&e2e_plain)?.trim();

    let id_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        hex::decode(id_str)
            .map_err(|e| anyhow!("identity key hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("identity seed must be 32 bytes"))?,
    );
    let e2e_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        hex::decode(e2e_str)
            .map_err(|e| anyhow!("e2e key hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("e2e seed must be 32 bytes"))?,
    );

    let signing = ed25519_dalek::SigningKey::from_bytes(&id_bytes);
    let verifying = signing.verifying_key();
    let e2e_sec = x25519_dalek::StaticSecret::from(*e2e_bytes);
    let e2e_pub = x25519_dalek::PublicKey::from(&e2e_sec);

    Ok(infnode::keyring::NodeKeys {
        signing,
        verifying,
        e2e_sec,
        e2e_pub,
    })
}

/// Save infnode NodeKeys (identity.key and e2e.key) with 0700 dir and 0600 files,
/// encrypting with STELL_NODE_PASSPHRASE if set.
pub fn save_node_keys(dir: &Path, keys: &infnode::keyring::NodeKeys) -> Result<()> {
    ensure_secure_dir(dir)?;
    let id_hex = Zeroizing::new(hex::encode(keys.signing.to_bytes()));
    let e2e_hex = Zeroizing::new(hex::encode(keys.e2e_sec.to_bytes()));

    let pass = Zeroizing::new(get_passphrase());
    let (id_blob, e2e_blob) = if let Some(p) = pass.as_deref() {
        (
            Zeroizing::new(encrypt_bytes(id_hex.as_bytes(), p)?),
            Zeroizing::new(encrypt_bytes(e2e_hex.as_bytes(), p)?),
        )
    } else {
        tracing::warn!("STELL_NODE_PASSPHRASE is not set: saving node keys in plaintext!");
        eprintln!("[WARN] STELL_NODE_PASSPHRASE is not set: saving node keys in plaintext!");
        (id_hex.clone(), e2e_hex.clone())
    };

    write_private_file(&dir.join("identity.key"), id_blob.as_bytes())?;
    write_private_file(&dir.join("e2e.key"), e2e_blob.as_bytes())?;
    Ok(())
}

/// Load or generate and save infnode NodeKeys.
pub fn load_or_generate_node_keys(dir: &Path) -> Result<infnode::keyring::NodeKeys> {
    if dir.join("identity.key").exists() {
        load_node_keys(dir)
    } else {
        let k = infnode::keyring::NodeKeys::generate();
        save_node_keys(dir, &k)?;
        Ok(k)
    }
}
