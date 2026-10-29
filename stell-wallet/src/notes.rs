//! Shielded Note Storage and Tracking for Stellereum Confidential Pool
//! Manages local encrypted note records stored in `~/.stellereum/shielded_notes.json`

use aead::{Aead, KeyInit, Payload};
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::security::enforce_strict_permissions;

pub const NOTES_STORE_VERSION: u32 = 1;
pub const NOTES_STORE_CIPHER: &str = "XChaCha20-Poly1305";
pub const NOTES_STORE_KDF: &str = "Argon2id(m=65536,t=3,p=4)";
pub const NOTES_AAD: &[u8] = b"STELL_SHIELDED_NOTES_STORE_V1";

/// Individual shielded note representing an unspent/spent commitment in the pool.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedNote {
    pub commitment: String,
    pub amount: u64,
    pub blinding: String,
    pub height: u64,
    pub spent: bool,
}

/// Encrypted container for shielded notes store (analogous to `HardenedKeystore`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardenedNotesStore {
    pub version: u32,
    pub cipher: String,
    pub kdf: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub auth_tag_hex: String,
}

impl HardenedNotesStore {
    /// Encrypt a slice of shielded notes with a user password using Argon2id + XChaCha20-Poly1305.
    pub fn encrypt(notes: &[ShieldedNote], password: &str) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Argon2 params error: {e:?}"))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 KDF failed: {e:?}"))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let plaintext =
            serde_json::to_vec(notes).map_err(|e| format!("Failed to serialize notes: {e}"))?;

        let payload = Payload {
            msg: &plaintext,
            aad: NOTES_AAD,
        };

        let ciphertext = cipher
            .encrypt(xnonce, payload)
            .map_err(|e| format!("Encryption error: {e:?}"))?;

        let tag_split = ciphertext.len().saturating_sub(16);
        let (ct_body, auth_tag) = ciphertext.split_at(tag_split);
        derived_key.zeroize();

        Ok(Self {
            version: NOTES_STORE_VERSION,
            cipher: NOTES_STORE_CIPHER.to_string(),
            kdf: NOTES_STORE_KDF.to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ct_body),
            auth_tag_hex: hex::encode(auth_tag),
        })
    }

    /// Decrypt notes container using password.
    pub fn decrypt(&self, password: &str) -> Result<Vec<ShieldedNote>, String> {
        if self.version != NOTES_STORE_VERSION {
            return Err(format!("Unsupported notes store version: {}", self.version));
        }
        if self.cipher != NOTES_STORE_CIPHER {
            return Err(format!("Unsupported cipher: {}", self.cipher));
        }

        let salt = hex::decode(&self.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
        let nonce = hex::decode(&self.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
        let ct_body =
            hex::decode(&self.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
        let auth_tag =
            hex::decode(&self.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Argon2 params error: {e:?}"))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 derivation error: {e:?}"))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let xnonce = XNonce::from_slice(&nonce);

        let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
        full_ct.extend_from_slice(&ct_body);
        full_ct.extend_from_slice(&auth_tag);

        let payload = Payload {
            msg: &full_ct,
            aad: NOTES_AAD,
        };

        let decrypted = cipher.decrypt(xnonce, payload).map_err(|_| {
            "Decryption failed: incorrect password or tampered notes container!".to_string()
        })?;

        derived_key.zeroize();
        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to parse decrypted notes JSON: {e}"))
    }

    /// Encrypt a slice of shielded notes with a master secret (32 bytes) using BLAKE3 KDF + XChaCha20-Poly1305.
    pub fn encrypt_with_secret(notes: &[ShieldedNote], secret: &[u8; 32]) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut material = [0u8; 48];
        material[..32].copy_from_slice(secret);
        material[32..].copy_from_slice(&salt);
        let derived_key = blake3::derive_key("STELL_NOTES_SECRET_KDF_V1", &material);

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let plaintext =
            serde_json::to_vec(notes).map_err(|e| format!("Failed to serialize notes: {e}"))?;

        let payload = Payload {
            msg: &plaintext,
            aad: NOTES_AAD,
        };

        let ciphertext = cipher
            .encrypt(xnonce, payload)
            .map_err(|e| format!("Encryption error: {e:?}"))?;

        let tag_split = ciphertext.len().saturating_sub(16);
        let (ct_body, auth_tag) = ciphertext.split_at(tag_split);

        Ok(Self {
            version: NOTES_STORE_VERSION,
            cipher: NOTES_STORE_CIPHER.to_string(),
            kdf: "Blake3(STELL_NOTES_SECRET_KDF_V1)".to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ct_body),
            auth_tag_hex: hex::encode(auth_tag),
        })
    }

    /// Decrypt notes container using a master secret (32 bytes).
    pub fn decrypt_with_secret(&self, secret: &[u8; 32]) -> Result<Vec<ShieldedNote>, String> {
        if self.version != NOTES_STORE_VERSION {
            return Err(format!("Unsupported notes store version: {}", self.version));
        }
        if self.cipher != NOTES_STORE_CIPHER {
            return Err(format!("Unsupported cipher: {}", self.cipher));
        }

        let salt = hex::decode(&self.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
        let nonce = hex::decode(&self.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
        let ct_body =
            hex::decode(&self.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
        let auth_tag =
            hex::decode(&self.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;

        let mut material = [0u8; 48];
        material[..32].copy_from_slice(secret);
        material[32..].copy_from_slice(&salt);
        let derived_key = blake3::derive_key("STELL_NOTES_SECRET_KDF_V1", &material);

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let xnonce = XNonce::from_slice(&nonce);

        let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
        full_ct.extend_from_slice(&ct_body);
        full_ct.extend_from_slice(&auth_tag);

        let payload = Payload {
            msg: &full_ct,
            aad: NOTES_AAD,
        };

        let decrypted = cipher.decrypt(xnonce, payload).map_err(|_| {
            "Decryption failed: incorrect secret or tampered notes container!".to_string()
        })?;

        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to parse decrypted notes JSON: {e}"))
    }

    /// Save encrypted container to disk using atomic rename (.tmp -> 0600 -> sync_all -> rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize HardenedNotesStore: {e}"))?;
        atomic_save_file(path, json.as_bytes())
    }

    /// Load encrypted container from disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read HardenedNotesStore from {:?}: {e}", path))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse HardenedNotesStore from {:?}: {e}", path))
    }
}

/// Derives a deterministic blinding factor (BIP-32 / HKDF style).
/// Uses `blake3::derive_key` with context `STELL_BLINDING_V1` from `(seed, note_counter)`.
/// This enables complete recovery of all shielded notes from a 24-word seed phrase.
pub fn derive_blinding_factor(seed: &[u8; 32], note_counter: u64) -> [u8; 32] {
    let mut attempt = 0u64;
    loop {
        let mut material = Vec::with_capacity(48);
        material.extend_from_slice(seed);
        material.extend_from_slice(&note_counter.to_le_bytes());
        if attempt > 0 {
            material.extend_from_slice(&attempt.to_le_bytes());
        }
        let derived = blake3::derive_key("STELL_BLINDING_V1", &material);
        if curve25519_dalek::scalar::Scalar::from_canonical_bytes(derived)
            .into_option()
            .is_some()
        {
            return derived;
        }
        attempt += 1;
    }
}

/// Locates the wallet keystore bytes bound to a notes/stealth store file.
///
/// Candidate search order (first hit wins):
/// 1. Per-wallet inference: `shielded_notes_<stem>.json` -> `<stem>.json`,
///    `stealth_outputs_<stem>.json` -> `<stem>.json` in the same directory.
/// 2. Legacy sibling: `<parent>/wallet.json`.
///
/// Returns an error when no keystore is found instead of deriving a key from
/// the public salt alone (fail-closed).
fn bound_wallet_bytes(store_path: &Path) -> Result<Vec<u8>, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(parent) = store_path.parent() {
        if let Some(fname) = store_path.file_name().and_then(|s| s.to_str()) {
            for prefix in ["shielded_notes_", "stealth_outputs_"] {
                if let Some(rest) = fname
                    .strip_prefix(prefix)
                    .and_then(|s| s.strip_suffix(".json"))
                {
                    if !rest.is_empty() && rest != "wallet" {
                        candidates.push(parent.join(format!("{rest}.json")));
                    }
                }
            }
            candidates.push(parent.join("wallet.json"));
        }
    }
    for cand in &candidates {
        if cand.exists() {
            match fs::read(cand) {
                Ok(data) if !data.is_empty() => return Ok(data),
                _ => continue,
            }
        }
    }
    Err(format!(
        "notes store at {:?} is not bound to any wallet keystore (tried {:?}); \
refusing to derive a key from the public salt alone. \
Use save_notes_with_secret/load_notes_with_secret (or the stealth *_with_secret variants) \
bound to the wallet master secret / password instead",
        store_path, candidates
    ))
}

/// Derives an encryption key for shielded notes storage bound to the local wallet.
///
/// SECURITY: this is a legacy-compatibility KDF. The bound `wallet.json` bytes are
/// an *encrypted* keystore (public ciphertext), so this key does NOT carry the secrecy
/// of the wallet password — it only binds the notes file to a wallet for isolation and
/// tamper-evidence. New code paths that already hold the decrypted master secret MUST
/// prefer `save_notes_with_secret` / `load_notes_with_secret` (BLAKE3 secret KDF) or the
/// Argon2id password variants, which are bound to a real secret.
///
/// Fail-closed: returns `Err` when no wallet keystore can be located next to `path`
/// instead of deriving a key from the public salt alone (which anyone holding the file
/// could recompute).
fn derive_storage_key(path: &Path, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let wallet_bytes = bound_wallet_bytes(path)?;
    let mut material = Vec::with_capacity(wallet_bytes.len() + salt.len());
    material.extend_from_slice(&wallet_bytes);
    material.extend_from_slice(salt);
    Ok(blake3::derive_key("STELL_NOTES_STORAGE_KEY_V1", &material))
}

/// Derives an encryption key for the stealth-outputs store bound to the local wallet.
///
/// Same fail-closed legacy-compatibility contract as [`derive_storage_key`] but under an
/// independent KDF context (`STELL_STEALTH_STORAGE_KEY_V1`) so a notes key can never be
/// reused as a stealth key and vice versa.
fn derive_stealth_storage_key(path: &Path, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let wallet_bytes = bound_wallet_bytes(path)?;
    let mut material = Vec::with_capacity(wallet_bytes.len() + salt.len());
    material.extend_from_slice(&wallet_bytes);
    material.extend_from_slice(salt);
    Ok(blake3::derive_key(
        "STELL_STEALTH_STORAGE_KEY_V1",
        &material,
    ))
}

/// Atomically saves data to disk:
/// 1. Writes to temporary file (`.tmp`) in the same parent directory
/// 2. Sets permissions strictly to 0600 (owner read/write only)
/// 3. Calls `sync_all()` to flush buffers and filesystem metadata to disk
/// 4. Atomically renames temporary file to destination path (`fs::rename`)
/// 5. Enforces strict file permissions on the final destination file
pub fn atomic_save_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create parent directory {:?}: {e}", parent))?;
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| format!("Invalid file path {:?}", path))?
        .to_string_lossy();
    let tmp_path = if let Some(parent) = path.parent() {
        parent.join(format!("{}.tmp", file_name))
    } else {
        PathBuf::from(format!("{}.tmp", file_name))
    };

    {
        use std::io::Write;
        let mut open_opts = fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }

        let mut file = open_opts
            .open(&tmp_path)
            .map_err(|e| format!("Failed to open temp notes file {:?}: {e}", tmp_path))?;

        file.write_all(data)
            .map_err(|e| format!("Failed to write temp notes file {:?}: {e}", tmp_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = file.metadata() {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&tmp_path, perms);
            }
        }

        file.sync_all()
            .map_err(|e| format!("Failed to sync temp notes file {:?}: {e}", tmp_path))?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {:?} to {:?}: {e}", tmp_path, path))?;

    enforce_strict_permissions(path);
    Ok(())
}

/// Default path for shielded notes storage (`~/.stellereum/shielded_notes.json`).
pub fn default_notes_path() -> PathBuf {
    stellereum::wallet::default_wallet_dir().join("shielded_notes.json")
}

/// Resolves the notes file location for a given wallet path, isolated per wallet.
///
/// - Legacy `wallet.json` (file stem `wallet`) keeps the historic sibling
///   `shielded_notes.json` unchanged.
/// - Any other wallet file `<stem>.json` (e.g. `wallets/trading.json`, an explicit
///   `--wallet rec_wallet.json`) maps to a sibling `shielded_notes_<stem>.json`, so
///   banknotes of different wallets never share one file.
/// - Backward compatibility: when the per-wallet file does not exist yet but the legacy
///   shared `shielded_notes.json` exists in the same directory, the legacy path is
///   returned so pre-existing stores keep loading (migrate them forward by re-saving).
pub fn notes_path_for_wallet(wallet_path: &Path) -> PathBuf {
    let Some(parent) = wallet_path.parent() else {
        return default_notes_path();
    };
    let stem = wallet_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if stem.is_empty() || stem == "wallet" {
        return parent.join("shielded_notes.json");
    }
    let per_wallet = parent.join(format!("shielded_notes_{stem}.json"));
    let legacy = parent.join("shielded_notes.json");
    if !per_wallet.exists() && legacy.exists() {
        return legacy;
    }
    per_wallet
}

/// Loads all shielded notes from disk. If the file does not exist, returns an empty list.
/// Decrypts XChaCha20-Poly1305 encrypted HardenedNotesStore container, or falls back to
/// legacy plaintext JSON.
pub fn load_notes(path: &Path) -> Result<Vec<ShieldedNote>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read shielded notes from {:?}: {e}", path))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Try parsing as encrypted HardenedNotesStore container
    if let Ok(store) = serde_json::from_str::<HardenedNotesStore>(trimmed) {
        if store.version != NOTES_STORE_VERSION {
            return Err(format!(
                "Unsupported notes store version: {}",
                store.version
            ));
        }
        if store.cipher != NOTES_STORE_CIPHER {
            return Err(format!("Unsupported notes store cipher: {}", store.cipher));
        }

        let salt = hex::decode(&store.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
        let nonce = hex::decode(&store.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
        let ct_body =
            hex::decode(&store.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
        let auth_tag =
            hex::decode(&store.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;

        if salt.len() != 16 {
            return Err("Invalid salt length in notes store".to_string());
        }
        let mut salt_arr = [0u8; 16];
        salt_arr.copy_from_slice(&salt);

        let key = derive_storage_key(path, &salt_arr)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let xnonce = XNonce::from_slice(&nonce);

        let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
        full_ct.extend_from_slice(&ct_body);
        full_ct.extend_from_slice(&auth_tag);

        let payload = Payload {
            msg: &full_ct,
            aad: NOTES_AAD,
        };

        let decrypted = cipher.decrypt(xnonce, payload).map_err(|_| {
            "Decryption failed: corrupted notes store or tampering detected!".to_string()
        })?;

        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to parse decrypted notes JSON: {e}"))
    } else {
        // Fallback: legacy plaintext JSON
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse shielded notes JSON from {:?}: {e}", path))
    }
}

/// Saves shielded notes to disk encrypted with XChaCha20-Poly1305 and enforces atomic persistence.
///
/// Legacy-compatibility path: the encryption key is bound to the sibling wallet
/// keystore via [`derive_storage_key`] (fail-closed when no wallet is found).
/// Callers that already hold the decrypted master secret MUST prefer
/// [`save_notes_with_secret`] (or [`save_notes_with_password`]), which are bound to a
/// real secret instead of public keystore bytes.
pub fn save_notes(path: &Path, notes: &[ShieldedNote]) -> Result<(), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_storage_key(path, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);

    let plaintext =
        serde_json::to_vec(notes).map_err(|e| format!("Failed to serialize notes: {e}"))?;

    let payload = Payload {
        msg: &plaintext,
        aad: NOTES_AAD,
    };

    let ciphertext = cipher
        .encrypt(xnonce, payload)
        .map_err(|e| format!("XChaCha20-Poly1305 encryption failed: {e:?}"))?;

    let tag_split = ciphertext.len().saturating_sub(16);
    let (ct_body, auth_tag) = ciphertext.split_at(tag_split);

    let store = HardenedNotesStore {
        version: NOTES_STORE_VERSION,
        cipher: NOTES_STORE_CIPHER.to_string(),
        kdf: "Blake3(STELL_NOTES_STORAGE_KEY_V1)".to_string(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ct_body),
        auth_tag_hex: hex::encode(auth_tag),
    };

    let json = serde_json::to_string_pretty(&store)
        .map_err(|e| format!("Failed to serialize HardenedNotesStore: {e}"))?;

    atomic_save_file(path, json.as_bytes())
}

/// Loads shielded notes from disk, decrypting with password if encrypted, or falling back
/// to legacy unencrypted plaintext JSON for smooth migration.
pub fn load_notes_with_password(path: &Path, password: &str) -> Result<Vec<ShieldedNote>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read shielded notes from {:?}: {e}", path))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(store) = serde_json::from_str::<HardenedNotesStore>(trimmed) {
        store.decrypt(password)
    } else {
        // Fallback: legacy plaintext JSON
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse legacy shielded notes JSON: {e}"))
    }
}

/// Saves shielded notes to disk encrypted with password using Argon2id + XChaCha20-Poly1305.
pub fn save_notes_with_password(
    path: &Path,
    notes: &[ShieldedNote],
    password: &str,
) -> Result<(), String> {
    let store = HardenedNotesStore::encrypt(notes, password)?;
    store.save(path)
}

/// Loads shielded notes from disk, decrypting with a 32-byte master secret if encrypted,
/// or falling back to legacy unencrypted plaintext JSON for smooth migration.
pub fn load_notes_with_secret(path: &Path, secret: &[u8; 32]) -> Result<Vec<ShieldedNote>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read shielded notes from {:?}: {e}", path))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(store) = serde_json::from_str::<HardenedNotesStore>(trimmed) {
        store.decrypt_with_secret(secret)
    } else {
        // Fallback: legacy plaintext JSON
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse legacy shielded notes JSON: {e}"))
    }
}

/// Saves shielded notes to disk encrypted with a 32-byte master secret using Blake3 KDF + XChaCha20-Poly1305.
pub fn save_notes_with_secret(
    path: &Path,
    notes: &[ShieldedNote],
    secret: &[u8; 32],
) -> Result<(), String> {
    let store = HardenedNotesStore::encrypt_with_secret(notes, secret)?;
    store.save(path)
}

/// Automatically appends a new shielded note into the store (secret-bound variant).
///
/// Preferred over [`add_note`] whenever the caller already holds the decrypted wallet
/// master secret: the whole file is re-encrypted under a key derived from that secret
/// (BLAKE3 KDF + XChaCha20-Poly1305) instead of the legacy wallet-bytes binding.
pub fn add_note_with_secret(
    path: &Path,
    note: ShieldedNote,
    secret: &[u8; 32],
) -> Result<(), String> {
    let mut notes = load_notes_with_secret(path, secret)?;
    if let Some(existing) = notes.iter_mut().find(|n| n.commitment == note.commitment) {
        *existing = note;
    } else {
        notes.push(note);
    }
    save_notes_with_secret(path, &notes, secret)
}

/// Automatically appends a new shielded note into the store (password-bound variant).
pub fn add_note_with_password(
    path: &Path,
    note: ShieldedNote,
    password: &str,
) -> Result<(), String> {
    let mut notes = load_notes_with_password(path, password)?;
    if let Some(existing) = notes.iter_mut().find(|n| n.commitment == note.commitment) {
        *existing = note;
    } else {
        notes.push(note);
    }
    save_notes_with_password(path, &notes, password)
}

/// Automatically appends a new shielded note into the store.
pub fn add_note(path: &Path, note: ShieldedNote) -> Result<(), String> {
    let mut notes = load_notes(path)?;
    // If commitment already exists, update it if unspent or deduplicate
    if let Some(existing) = notes.iter_mut().find(|n| n.commitment == note.commitment) {
        *existing = note;
    } else {
        notes.push(note);
    }
    save_notes(path, &notes)
}

/// Returns all unspent notes from the note store.
pub fn get_unspent_notes(path: &Path) -> Result<Vec<ShieldedNote>, String> {
    let notes = load_notes(path)?;
    Ok(notes.into_iter().filter(|n| !n.spent).collect())
}

/// Returns all unspent notes from a secret-bound store.
pub fn get_unspent_notes_with_secret(
    path: &Path,
    secret: &[u8; 32],
) -> Result<Vec<ShieldedNote>, String> {
    let notes = load_notes_with_secret(path, secret)?;
    Ok(notes.into_iter().filter(|n| !n.spent).collect())
}

/// Returns all unspent notes from a password-bound store.
pub fn get_unspent_notes_with_password(
    path: &Path,
    password: &str,
) -> Result<Vec<ShieldedNote>, String> {
    let notes = load_notes_with_password(path, password)?;
    Ok(notes.into_iter().filter(|n| !n.spent).collect())
}

/// Calculates the total shielded balance (in nano-STELL) from a slice of notes.
pub fn calculate_shielded_balance(notes: &[ShieldedNote]) -> u64 {
    notes
        .iter()
        .filter(|n| !n.spent)
        .fold(0u64, |acc, n| acc.saturating_add(n.amount))
}

/// Selects unspent notes matching `target_amount` (nano-STELL).
/// Prefers a single exact-match note; otherwise finds a subset whose sum matches `target_amount`.
pub fn select_notes_for_unshield(
    path: &Path,
    target_amount: u64,
) -> Result<Vec<ShieldedNote>, String> {
    let unspent = get_unspent_notes(path)?;
    select_from_unspent(&unspent, target_amount)
}

/// Secret-bound variant of [`select_notes_for_unshield`].
pub fn select_notes_for_unshield_with_secret(
    path: &Path,
    target_amount: u64,
    secret: &[u8; 32],
) -> Result<Vec<ShieldedNote>, String> {
    let unspent = get_unspent_notes_with_secret(path, secret)?;
    select_from_unspent(&unspent, target_amount)
}

/// Password-bound variant of [`select_notes_for_unshield`].
pub fn select_notes_for_unshield_with_password(
    path: &Path,
    target_amount: u64,
    password: &str,
) -> Result<Vec<ShieldedNote>, String> {
    let unspent = get_unspent_notes_with_password(path, password)?;
    select_from_unspent(&unspent, target_amount)
}

fn select_from_unspent(
    unspent: &[ShieldedNote],
    target_amount: u64,
) -> Result<Vec<ShieldedNote>, String> {
    if unspent.is_empty() {
        return Err("No unspent shielded notes found in wallet".to_string());
    }

    let total_unspent = calculate_shielded_balance(unspent);
    if total_unspent < target_amount {
        return Err(format!(
            "Insufficient shielded balance: available {} nano-STELL ({:.6} STELL), requested {} nano-STELL ({:.6} STELL)",
            total_unspent,
            (total_unspent as f64) / 1_000_000_000.0,
            target_amount,
            (target_amount as f64) / 1_000_000_000.0
        ));
    }

    // 1. Try single exact note match
    if let Some(note) = unspent.iter().find(|n| n.amount == target_amount) {
        return Ok(vec![note.clone()]);
    }

    // 2. Subset sum search for combinations matching exact target
    fn find_subset(
        notes: &[ShieldedNote],
        idx: usize,
        current_sum: u64,
        target: u64,
        chosen: &mut Vec<usize>,
    ) -> bool {
        if current_sum == target {
            return true;
        }
        if current_sum > target || idx >= notes.len() {
            return false;
        }

        // Try including notes[idx]
        chosen.push(idx);
        if find_subset(
            notes,
            idx + 1,
            current_sum + notes[idx].amount,
            target,
            chosen,
        ) {
            return true;
        }
        chosen.pop();

        // Try skipping notes[idx]
        find_subset(notes, idx + 1, current_sum, target, chosen)
    }

    let mut chosen_indices = Vec::new();
    if find_subset(unspent, 0, 0, target_amount, &mut chosen_indices) {
        let selected = chosen_indices
            .into_iter()
            .map(|i| unspent[i].clone())
            .collect();
        return Ok(selected);
    }

    Err(format!(
        "No combination of unspent shielded notes sums exactly to {} nano-STELL ({:.6} STELL). Available notes: {:?}",
        target_amount,
        (target_amount as f64) / 1_000_000_000.0,
        unspent.iter().map(|n| n.amount).collect::<Vec<_>>()
    ))
}

/// Marks notes with matching commitments as spent in the store.
pub fn mark_notes_spent(path: &Path, commitments: &[String]) -> Result<(), String> {
    let mut notes = load_notes(path)?;
    for note in &mut notes {
        if commitments
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&note.commitment))
        {
            note.spent = true;
        }
    }
    save_notes(path, &notes)
}

/// Secret-bound variant of [`mark_notes_spent`].
pub fn mark_notes_spent_with_secret(
    path: &Path,
    commitments: &[String],
    secret: &[u8; 32],
) -> Result<(), String> {
    let mut notes = load_notes_with_secret(path, secret)?;
    for note in &mut notes {
        if commitments
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&note.commitment))
        {
            note.spent = true;
        }
    }
    save_notes_with_secret(path, &notes, secret)
}

/// Password-bound variant of [`mark_notes_spent`].
pub fn mark_notes_spent_with_password(
    path: &Path,
    commitments: &[String],
    password: &str,
) -> Result<(), String> {
    let mut notes = load_notes_with_password(path, password)?;
    for note in &mut notes {
        if commitments
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&note.commitment))
        {
            note.spent = true;
        }
    }
    save_notes_with_password(path, &notes, password)
}

/// Individual stealth output detected during blockchain scanning.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthOutput {
    /// One-time destination address (32-byte hex)
    pub one_time_pub: String,
    /// Ephemeral public key carried in tx payload (32-byte hex)
    pub ephemeral_pub: String,
    /// Shared secret derived between view_priv and ephemeral_pub (32-byte hex)
    pub shared_secret: String,
    /// Received amount in nano-STELL
    pub amount: u64,
    /// Block height where payment was included
    pub height: u64,
    /// Transaction hash (hex)
    pub tx_hash: String,
    /// Spent status
    pub spent: bool,
}

pub const STEALTH_STORE_VERSION: u32 = 1;
pub const STEALTH_STORE_CIPHER: &str = "XChaCha20-Poly1305";
pub const STEALTH_STORE_KDF: &str = "Argon2id(m=65536,t=3,p=4)";
pub const STEALTH_AAD: &[u8] = b"STELL_STEALTH_OUTPUTS_STORE_V1";

/// Encrypted container for the stealth-outputs store (mirrors [`HardenedNotesStore`]
/// but under an independent AAD and KDF contexts so notes and stealth ciphertexts can
/// never be confused).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardenedStealthStore {
    pub version: u32,
    pub cipher: String,
    pub kdf: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub auth_tag_hex: String,
}

impl HardenedStealthStore {
    /// Encrypt stealth outputs with a user password (Argon2id + XChaCha20-Poly1305).
    pub fn encrypt(outputs: &[StealthOutput], password: &str) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Argon2 params error: {e:?}"))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 KDF failed: {e:?}"))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let plaintext = serde_json::to_vec(outputs)
            .map_err(|e| format!("Failed to serialize stealth outputs: {e}"))?;
        let payload = Payload {
            msg: &plaintext,
            aad: STEALTH_AAD,
        };
        let ciphertext = cipher
            .encrypt(xnonce, payload)
            .map_err(|e| format!("Encryption error: {e:?}"))?;
        let tag_split = ciphertext.len().saturating_sub(16);
        let (ct_body, auth_tag) = ciphertext.split_at(tag_split);
        derived_key.zeroize();

        Ok(Self {
            version: STEALTH_STORE_VERSION,
            cipher: STEALTH_STORE_CIPHER.to_string(),
            kdf: STEALTH_STORE_KDF.to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ct_body),
            auth_tag_hex: hex::encode(auth_tag),
        })
    }

    /// Decrypt stealth outputs with a user password.
    pub fn decrypt(&self, password: &str) -> Result<Vec<StealthOutput>, String> {
        if self.version != STEALTH_STORE_VERSION {
            return Err(format!(
                "Unsupported stealth store version: {}",
                self.version
            ));
        }
        if self.cipher != STEALTH_STORE_CIPHER {
            return Err(format!("Unsupported stealth store cipher: {}", self.cipher));
        }
        let salt = hex::decode(&self.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
        let nonce = hex::decode(&self.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
        let ct_body =
            hex::decode(&self.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
        let auth_tag =
            hex::decode(&self.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| format!("Argon2 params error: {e:?}"))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
            .map_err(|e| format!("Argon2 derivation error: {e:?}"))?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let xnonce = XNonce::from_slice(&nonce);
        let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
        full_ct.extend_from_slice(&ct_body);
        full_ct.extend_from_slice(&auth_tag);
        let payload = Payload {
            msg: &full_ct,
            aad: STEALTH_AAD,
        };
        let decrypted = cipher.decrypt(xnonce, payload).map_err(|_| {
            "Decryption failed: incorrect password or tampered stealth container!".to_string()
        })?;
        derived_key.zeroize();
        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to parse decrypted stealth JSON: {e}"))
    }

    /// Encrypt stealth outputs with a 32-byte master secret (BLAKE3 KDF + XChaCha20-Poly1305).
    pub fn encrypt_with_secret(
        outputs: &[StealthOutput],
        secret: &[u8; 32],
    ) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut material = [0u8; 48];
        material[..32].copy_from_slice(secret);
        material[32..].copy_from_slice(&salt);
        let derived_key = blake3::derive_key("STELL_STEALTH_SECRET_KDF_V1", &material);

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let plaintext = serde_json::to_vec(outputs)
            .map_err(|e| format!("Failed to serialize stealth outputs: {e}"))?;
        let payload = Payload {
            msg: &plaintext,
            aad: STEALTH_AAD,
        };
        let ciphertext = cipher
            .encrypt(xnonce, payload)
            .map_err(|e| format!("Encryption error: {e:?}"))?;
        let tag_split = ciphertext.len().saturating_sub(16);
        let (ct_body, auth_tag) = ciphertext.split_at(tag_split);

        Ok(Self {
            version: STEALTH_STORE_VERSION,
            cipher: STEALTH_STORE_CIPHER.to_string(),
            kdf: "Blake3(STELL_STEALTH_SECRET_KDF_V1)".to_string(),
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ct_body),
            auth_tag_hex: hex::encode(auth_tag),
        })
    }

    /// Decrypt stealth outputs with a 32-byte master secret.
    pub fn decrypt_with_secret(&self, secret: &[u8; 32]) -> Result<Vec<StealthOutput>, String> {
        if self.version != STEALTH_STORE_VERSION {
            return Err(format!(
                "Unsupported stealth store version: {}",
                self.version
            ));
        }
        if self.cipher != STEALTH_STORE_CIPHER {
            return Err(format!("Unsupported stealth store cipher: {}", self.cipher));
        }
        let salt = hex::decode(&self.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
        let nonce = hex::decode(&self.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
        let ct_body =
            hex::decode(&self.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
        let auth_tag =
            hex::decode(&self.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;

        let mut material = [0u8; 48];
        material[..32].copy_from_slice(secret);
        material[32..].copy_from_slice(&salt);
        let derived_key = blake3::derive_key("STELL_STEALTH_SECRET_KDF_V1", &material);

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let xnonce = XNonce::from_slice(&nonce);
        let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
        full_ct.extend_from_slice(&ct_body);
        full_ct.extend_from_slice(&auth_tag);
        let payload = Payload {
            msg: &full_ct,
            aad: STEALTH_AAD,
        };
        let decrypted = cipher.decrypt(xnonce, payload).map_err(|_| {
            "Decryption failed: incorrect secret or tampered stealth container!".to_string()
        })?;
        serde_json::from_slice(&decrypted)
            .map_err(|e| format!("Failed to parse decrypted stealth JSON: {e}"))
    }

    /// Save encrypted container atomically (.tmp -> 0600 -> sync_all -> rename).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize HardenedStealthStore: {e}"))?;
        atomic_save_file(path, json.as_bytes())
    }

    /// Load encrypted container from disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read HardenedStealthStore from {:?}: {e}", path))?;
        serde_json::from_str(&data)
            .map_err(|e| format!("Failed to parse HardenedStealthStore from {:?}: {e}", path))
    }
}

pub fn default_stealth_outputs_path() -> PathBuf {
    stellereum::wallet::default_wallet_dir().join("stealth_outputs.json")
}

/// Resolves the stealth-outputs file location for a given wallet path, isolated per wallet.
///
/// Mirrors [`notes_path_for_wallet`]: legacy `wallet.json` keeps the historic sibling
/// `stealth_outputs.json`; any other `<stem>.json` maps to `stealth_outputs_<stem>.json`.
/// Backward compatibility: when the per-wallet file does not exist yet but the legacy
/// shared `stealth_outputs.json` exists in the same directory, the legacy path is
/// returned so pre-existing stores keep loading.
pub fn stealth_path_for_wallet(wallet_path: &Path) -> PathBuf {
    let Some(parent) = wallet_path.parent() else {
        return default_stealth_outputs_path();
    };
    let stem = wallet_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if stem.is_empty() || stem == "wallet" {
        return parent.join("stealth_outputs.json");
    }
    let per_wallet = parent.join(format!("stealth_outputs_{stem}.json"));
    let legacy = parent.join("stealth_outputs.json");
    if !per_wallet.exists() && legacy.exists() {
        return legacy;
    }
    per_wallet
}

fn decrypt_stealth_store_with_storage_key(
    path: &Path,
    store: &HardenedStealthStore,
) -> Result<Vec<StealthOutput>, String> {
    if store.version != STEALTH_STORE_VERSION {
        return Err(format!(
            "Unsupported stealth store version: {}",
            store.version
        ));
    }
    if store.cipher != STEALTH_STORE_CIPHER {
        return Err(format!(
            "Unsupported stealth store cipher: {}",
            store.cipher
        ));
    }
    let salt = hex::decode(&store.salt_hex).map_err(|e| format!("Corrupted salt: {e}"))?;
    let nonce = hex::decode(&store.nonce_hex).map_err(|e| format!("Corrupted nonce: {e}"))?;
    let ct_body =
        hex::decode(&store.ciphertext_hex).map_err(|e| format!("Corrupted ciphertext: {e}"))?;
    let auth_tag =
        hex::decode(&store.auth_tag_hex).map_err(|e| format!("Corrupted auth tag: {e}"))?;
    if salt.len() != 16 {
        return Err("Invalid salt length in stealth store".to_string());
    }
    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(&salt);

    let key = derive_stealth_storage_key(path, &salt_arr)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let xnonce = XNonce::from_slice(&nonce);
    let mut full_ct = Vec::with_capacity(ct_body.len() + auth_tag.len());
    full_ct.extend_from_slice(&ct_body);
    full_ct.extend_from_slice(&auth_tag);
    let payload = Payload {
        msg: &full_ct,
        aad: STEALTH_AAD,
    };
    let decrypted = cipher.decrypt(xnonce, payload).map_err(|_| {
        "Decryption failed: corrupted stealth store or tampering detected!".to_string()
    })?;
    serde_json::from_slice(&decrypted)
        .map_err(|e| format!("Failed to parse decrypted stealth JSON: {e}"))
}

/// Loads stealth outputs, decrypting the XChaCha20-Poly1305 [`HardenedStealthStore`]
/// container (legacy wallet-bound key) or falling back to legacy plaintext JSON for
/// smooth migration of pre-encryption files.
pub fn load_stealth_outputs(path: &Path) -> Result<Vec<StealthOutput>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read stealth outputs from {:?}: {e}", path))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(store) = serde_json::from_str::<HardenedStealthStore>(trimmed) {
        decrypt_stealth_store_with_storage_key(path, &store)
    } else {
        // Fallback: legacy plaintext JSON (pre-encryption files)
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse stealth outputs JSON: {e}"))
    }
}

/// Saves stealth outputs encrypted with XChaCha20-Poly1305 (legacy wallet-bound key)
/// using atomic persistence (.tmp -> 0600 -> sync_all -> rename).
pub fn save_stealth_outputs(path: &Path, outputs: &[StealthOutput]) -> Result<(), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_stealth_storage_key(path, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);

    let plaintext = serde_json::to_vec(outputs)
        .map_err(|e| format!("Failed to serialize stealth outputs: {e}"))?;
    let payload = Payload {
        msg: &plaintext,
        aad: STEALTH_AAD,
    };
    let ciphertext = cipher
        .encrypt(xnonce, payload)
        .map_err(|e| format!("XChaCha20-Poly1305 encryption failed: {e:?}"))?;
    let tag_split = ciphertext.len().saturating_sub(16);
    let (ct_body, auth_tag) = ciphertext.split_at(tag_split);

    let store = HardenedStealthStore {
        version: STEALTH_STORE_VERSION,
        cipher: STEALTH_STORE_CIPHER.to_string(),
        kdf: "Blake3(STELL_STEALTH_STORAGE_KEY_V1)".to_string(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ct_body),
        auth_tag_hex: hex::encode(auth_tag),
    };
    let json = serde_json::to_string_pretty(&store)
        .map_err(|e| format!("Failed to serialize HardenedStealthStore: {e}"))?;
    atomic_save_file(path, json.as_bytes())
}

/// Loads stealth outputs decrypting with a password (or legacy plaintext migration).
pub fn load_stealth_outputs_with_password(
    path: &Path,
    password: &str,
) -> Result<Vec<StealthOutput>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read stealth outputs from {:?}: {e}", path))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(store) = serde_json::from_str::<HardenedStealthStore>(trimmed) {
        store.decrypt(password)
    } else {
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse legacy stealth outputs JSON: {e}"))
    }
}

/// Saves stealth outputs encrypted with a password (Argon2id + XChaCha20-Poly1305).
pub fn save_stealth_outputs_with_password(
    path: &Path,
    outputs: &[StealthOutput],
    password: &str,
) -> Result<(), String> {
    let store = HardenedStealthStore::encrypt(outputs, password)?;
    store.save(path)
}

/// Loads stealth outputs decrypting with a 32-byte master secret.
///
/// Migration chain: secret-encrypted -> legacy wallet-bound [`HardenedStealthStore`] ->
/// legacy plaintext JSON. The wallet-bound fallback keeps pre-migration files readable
/// right after upgrading; new writes via [`save_stealth_outputs_with_secret`] are always
/// secret-bound.
pub fn load_stealth_outputs_with_secret(
    path: &Path,
    secret: &[u8; 32],
) -> Result<Vec<StealthOutput>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read stealth outputs from {:?}: {e}", path))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(store) = serde_json::from_str::<HardenedStealthStore>(trimmed) {
        match store.decrypt_with_secret(secret) {
            Ok(v) => Ok(v),
            Err(secret_err) => match decrypt_stealth_store_with_storage_key(path, &store) {
                Ok(v) => Ok(v),
                Err(_) => Err(secret_err),
            },
        }
    } else {
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse legacy stealth outputs JSON: {e}"))
    }
}

/// Saves stealth outputs encrypted with a 32-byte master secret (preferred path).
pub fn save_stealth_outputs_with_secret(
    path: &Path,
    outputs: &[StealthOutput],
    secret: &[u8; 32],
) -> Result<(), String> {
    let store = HardenedStealthStore::encrypt_with_secret(outputs, secret)?;
    store.save(path)
}

fn stealth_is_duplicate(outputs: &[StealthOutput], output: &StealthOutput) -> bool {
    outputs.iter().any(|o| {
        o.one_time_pub.eq_ignore_ascii_case(&output.one_time_pub)
            || o.tx_hash.eq_ignore_ascii_case(&output.tx_hash)
    })
}

pub fn add_stealth_output(path: &Path, output: StealthOutput) -> Result<bool, String> {
    let mut outputs = load_stealth_outputs(path)?;
    if stealth_is_duplicate(&outputs, &output) {
        return Ok(false);
    }
    outputs.push(output);
    save_stealth_outputs(path, &outputs)?;
    Ok(true)
}

/// Secret-bound variant of [`add_stealth_output`] (preferred when the master secret is
/// available, e.g. right after unlocking the keystore).
pub fn add_stealth_output_with_secret(
    path: &Path,
    output: StealthOutput,
    secret: &[u8; 32],
) -> Result<bool, String> {
    let mut outputs = load_stealth_outputs_with_secret(path, secret)?;
    if stealth_is_duplicate(&outputs, &output) {
        return Ok(false);
    }
    outputs.push(output);
    save_stealth_outputs_with_secret(path, &outputs, secret)?;
    Ok(true)
}

/// Password-bound variant of [`add_stealth_output`].
pub fn add_stealth_output_with_password(
    path: &Path,
    output: StealthOutput,
    password: &str,
) -> Result<bool, String> {
    let mut outputs = load_stealth_outputs_with_password(path, password)?;
    if stealth_is_duplicate(&outputs, &output) {
        return Ok(false);
    }
    outputs.push(output);
    save_stealth_outputs_with_password(path, &outputs, password)?;
    Ok(true)
}

pub fn get_unspent_stealth_outputs(path: &Path) -> Result<Vec<StealthOutput>, String> {
    let outputs = load_stealth_outputs(path)?;
    Ok(outputs.into_iter().filter(|o| !o.spent).collect())
}

/// Secret-bound variant of [`get_unspent_stealth_outputs`].
pub fn get_unspent_stealth_outputs_with_secret(
    path: &Path,
    secret: &[u8; 32],
) -> Result<Vec<StealthOutput>, String> {
    let outputs = load_stealth_outputs_with_secret(path, secret)?;
    Ok(outputs.into_iter().filter(|o| !o.spent).collect())
}

pub fn mark_stealth_output_spent(path: &Path, one_time_pub: &str) -> Result<bool, String> {
    let mut outputs = load_stealth_outputs(path)?;
    let mut found = false;
    for o in &mut outputs {
        if o.one_time_pub.eq_ignore_ascii_case(one_time_pub) {
            o.spent = true;
            found = true;
        }
    }
    if found {
        save_stealth_outputs(path, &outputs)?;
    }
    Ok(found)
}

/// Secret-bound variant of [`mark_stealth_output_spent`].
pub fn mark_stealth_output_spent_with_secret(
    path: &Path,
    one_time_pub: &str,
    secret: &[u8; 32],
) -> Result<bool, String> {
    let mut outputs = load_stealth_outputs_with_secret(path, secret)?;
    let mut found = false;
    for o in &mut outputs {
        if o.one_time_pub.eq_ignore_ascii_case(one_time_pub) {
            o.spent = true;
            found = true;
        }
    }
    if found {
        save_stealth_outputs_with_secret(path, &outputs, secret)?;
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a dummy wallet keystore next to a store file so the legacy
    /// wallet-bound KDF has binding material (fail-closed otherwise).
    fn write_dummy_wallet_binding(store_path: &Path) {
        let parent = store_path.parent().expect("store path must have a parent");
        let _ = fs::create_dir_all(parent);
        let fname = store_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        // Mirror `bound_wallet_bytes` inference: per-wallet stores bind to
        // `<stem>.json`, legacy stores bind to `wallet.json`.
        let wallet_name =
            if fname.starts_with("shielded_notes_") || fname.starts_with("stealth_outputs_") {
                let stem = fname
                    .strip_prefix("shielded_notes_")
                    .or_else(|| fname.strip_prefix("stealth_outputs_"))
                    .and_then(|s| s.strip_suffix(".json"))
                    .filter(|s| !s.is_empty())
                    .unwrap_or("wallet");
                format!("{stem}.json")
            } else {
                "wallet.json".to_string()
            };
        let wallet_path = parent.join(wallet_name);
        if !wallet_path.exists() {
            let _ = fs::write(&wallet_path, b"{\"dummy\":\"wallet-binding-for-tests\"}");
        }
    }

    #[test]
    fn test_stealth_outputs_store_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("stell_stealth_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let stealth_file = temp_dir.join("stealth_outputs.json");
        write_dummy_wallet_binding(&stealth_file);

        let out1 = StealthOutput {
            one_time_pub: "11".repeat(32),
            ephemeral_pub: "22".repeat(32),
            shared_secret: "33".repeat(32),
            amount: 15_000_000_000,
            height: 100,
            tx_hash: "44".repeat(32),
            spent: false,
        };

        assert!(add_stealth_output(&stealth_file, out1.clone()).unwrap());
        // Duplicate rejected
        assert!(!add_stealth_output(&stealth_file, out1.clone()).unwrap());

        let unspent = get_unspent_stealth_outputs(&stealth_file).unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].one_time_pub, out1.one_time_pub);

        assert!(mark_stealth_output_spent(&stealth_file, &out1.one_time_pub).unwrap());
        let unspent_after = get_unspent_stealth_outputs(&stealth_file).unwrap();
        assert!(unspent_after.is_empty());

        // File on disk must be an encrypted XChaCha20-Poly1305 container, atomically
        // persisted (no lingering .tmp), with 0600 permissions and no cleartext secrets.
        let raw_disk = fs::read_to_string(&stealth_file).unwrap();
        assert!(
            raw_disk.contains("XChaCha20-Poly1305"),
            "stealth file must be encrypted"
        );
        assert!(
            raw_disk.contains("ciphertext_hex"),
            "stealth file must carry ciphertext"
        );
        assert!(
            !raw_disk.contains("15000000000"),
            "amounts must NOT appear in cleartext"
        );
        assert!(
            !raw_disk.contains(&out1.shared_secret),
            "shared secrets must NOT appear in cleartext"
        );
        assert!(
            !temp_dir.join("stealth_outputs.json.tmp").exists(),
            ".tmp must be renamed"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&stealth_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "stealth file must be 0600");
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_storage_key_fail_closed_without_wallet_binding() {
        let temp_dir =
            std::env::temp_dir().join(format!("stell_nobind_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        // Deliberately NO wallet.json here.
        let notes_file = temp_dir.join("shielded_notes.json");
        let stealth_file = temp_dir.join("stealth_outputs.json");

        let note = ShieldedNote {
            commitment: "c1".to_string(),
            amount: 1,
            blinding: "b1".to_string(),
            height: 0,
            spent: false,
        };
        let save_err = save_notes(&notes_file, &[note]).unwrap_err();
        assert!(
            save_err.contains("not bound to any wallet"),
            "must fail closed, got: {save_err}"
        );
        assert!(
            !notes_file.exists(),
            "failed save must not leave a file behind"
        );

        let out = StealthOutput {
            one_time_pub: "11".repeat(32),
            ephemeral_pub: "22".repeat(32),
            shared_secret: "33".repeat(32),
            amount: 1,
            height: 0,
            tx_hash: "44".repeat(32),
            spent: false,
        };
        let s_err = save_stealth_outputs(&stealth_file, &[out]).unwrap_err();
        assert!(
            s_err.contains("not bound to any wallet"),
            "must fail closed, got: {s_err}"
        );
        assert!(!stealth_file.exists());

        // Secret-bound paths do NOT need a wallet file and keep working.
        let secret = [0x5Au8; 32];
        let secret_notes = temp_dir.join("secret_notes.json");
        save_notes_with_secret(
            &secret_notes,
            &[ShieldedNote {
                commitment: "s1".to_string(),
                amount: 9,
                blinding: "sb".to_string(),
                height: 1,
                spent: false,
            }],
            &secret,
        )
        .unwrap();
        assert_eq!(
            load_notes_with_secret(&secret_notes, &secret)
                .unwrap()
                .len(),
            1
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_per_wallet_notes_and_stealth_path_isolation() {
        let base =
            std::env::temp_dir().join(format!("stell_isolation_test_{}", rand::random::<u64>()));
        let wallets_dir = base.join("wallets");
        let _ = fs::create_dir_all(&wallets_dir);

        // Legacy wallet keeps historic sibling names.
        let legacy_wallet = base.join("wallet.json");
        assert_eq!(
            notes_path_for_wallet(&legacy_wallet),
            base.join("shielded_notes.json")
        );
        assert_eq!(
            stealth_path_for_wallet(&legacy_wallet),
            base.join("stealth_outputs.json")
        );

        // Named wallets get isolated per-wallet stores.
        let trading = wallets_dir.join("trading.json");
        let savings = wallets_dir.join("savings.json");
        assert_eq!(
            notes_path_for_wallet(&trading),
            wallets_dir.join("shielded_notes_trading.json")
        );
        assert_eq!(
            notes_path_for_wallet(&savings),
            wallets_dir.join("shielded_notes_savings.json")
        );
        assert_ne!(
            notes_path_for_wallet(&trading),
            notes_path_for_wallet(&savings)
        );
        assert_eq!(
            stealth_path_for_wallet(&trading),
            wallets_dir.join("stealth_outputs_trading.json")
        );
        assert_ne!(
            stealth_path_for_wallet(&trading),
            stealth_path_for_wallet(&savings)
        );

        // Backward compatibility: legacy shared file is reused when per-wallet is absent.
        let _ = fs::write(&legacy_wallet, b"dummy");
        let other = base.join("other.json");
        let _ = fs::write(base.join("shielded_notes.json"), b"[]");
        assert_eq!(
            notes_path_for_wallet(&other),
            base.join("shielded_notes.json")
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_stealth_secret_and_password_roundtrip_with_tamper_rejection() {
        let temp_dir =
            std::env::temp_dir().join(format!("stell_stealth_sec_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);

        let out = StealthOutput {
            one_time_pub: "aa".repeat(32),
            ephemeral_pub: "bb".repeat(32),
            shared_secret: "cc".repeat(32),
            amount: 42_000_000_000,
            height: 7,
            tx_hash: "dd".repeat(32),
            spent: false,
        };
        let outputs = vec![out.clone()];

        // Password roundtrip + wrong-password + tamper rejection.
        let pw = "StealthPw#2026";
        let store = HardenedStealthStore::encrypt(&outputs, pw).unwrap();
        assert_eq!(store.decrypt(pw).unwrap(), outputs);
        assert!(store.decrypt("wrong").is_err());
        let mut tampered = store.clone();
        let mut ct = hex::decode(&tampered.ciphertext_hex).unwrap();
        ct[0] ^= 0xFF;
        tampered.ciphertext_hex = hex::encode(ct);
        assert!(tampered.decrypt(pw).is_err());

        // Secret roundtrip + wrong-secret rejection + file-level helpers.
        let secret = [0x71u8; 32];
        let f = temp_dir.join("stealth_outputs.json");
        assert!(add_stealth_output_with_secret(&f, out.clone(), &secret).unwrap());
        assert!(!add_stealth_output_with_secret(&f, out.clone(), &secret).unwrap());
        assert_eq!(
            get_unspent_stealth_outputs_with_secret(&f, &secret)
                .unwrap()
                .len(),
            1
        );
        assert!(mark_stealth_output_spent_with_secret(&f, &out.one_time_pub, &secret).unwrap());
        assert!(get_unspent_stealth_outputs_with_secret(&f, &secret)
            .unwrap()
            .is_empty());
        assert!(get_unspent_stealth_outputs_with_secret(&f, &[0x72u8; 32]).is_err());
        let raw = fs::read_to_string(&f).unwrap();
        assert!(raw.contains("XChaCha20-Poly1305"));
        assert!(!raw.contains("42000000000"));

        // Legacy plaintext stealth file migrates transparently into the secret loader.
        let legacy = temp_dir.join("legacy_stealth.json");
        fs::write(&legacy, serde_json::to_string_pretty(&outputs).unwrap()).unwrap();
        assert_eq!(
            load_stealth_outputs_with_secret(&legacy, &secret).unwrap(),
            outputs
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_notes_secret_helpers_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("stell_notes_sec_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let f = temp_dir.join("shielded_notes.json");
        let secret = [0x33u8; 32];

        add_note_with_secret(
            &f,
            ShieldedNote {
                commitment: "k1".to_string(),
                amount: 5_000_000_000,
                blinding: "x".to_string(),
                height: 1,
                spent: false,
            },
            &secret,
        )
        .unwrap();
        add_note_with_secret(
            &f,
            ShieldedNote {
                commitment: "k2".to_string(),
                amount: 10_000_000_000,
                blinding: "y".to_string(),
                height: 2,
                spent: false,
            },
            &secret,
        )
        .unwrap();
        assert_eq!(get_unspent_notes_with_secret(&f, &secret).unwrap().len(), 2);
        let sel = select_notes_for_unshield_with_secret(&f, 15_000_000_000, &secret).unwrap();
        assert_eq!(sel.len(), 2);
        mark_notes_spent_with_secret(&f, &["k1".to_string()], &secret).unwrap();
        assert_eq!(get_unspent_notes_with_secret(&f, &secret).unwrap().len(), 1);
        assert!(get_unspent_notes_with_secret(&f, &[0x44u8; 32]).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_note_selection_exact_and_combination() {
        let temp_dir =
            std::env::temp_dir().join(format!("stell_notes_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let notes_file = temp_dir.join("shielded_notes.json");
        write_dummy_wallet_binding(&notes_file);

        let n1 = ShieldedNote {
            commitment: "c1".to_string(),
            amount: 5_000_000_000,
            blinding: "b1".to_string(),
            height: 10,
            spent: false,
        };
        let n2 = ShieldedNote {
            commitment: "c2".to_string(),
            amount: 10_000_000_000,
            blinding: "b2".to_string(),
            height: 11,
            spent: false,
        };
        let n3 = ShieldedNote {
            commitment: "c3".to_string(),
            amount: 20_000_000_000,
            blinding: "b3".to_string(),
            height: 12,
            spent: false,
        };

        add_note(&notes_file, n1).unwrap();
        add_note(&notes_file, n2).unwrap();
        add_note(&notes_file, n3).unwrap();

        let all = load_notes(&notes_file).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(calculate_shielded_balance(&all), 35_000_000_000);

        // Verify the file on disk is encrypted (XChaCha20-Poly1305 HardenedNotesStore)
        let raw_disk = fs::read_to_string(&notes_file).unwrap();
        assert!(
            raw_disk.contains("XChaCha20-Poly1305"),
            "On-disk file must be encrypted container"
        );
        assert!(
            raw_disk.contains("ciphertext_hex"),
            "On-disk file must have ciphertext"
        );
        assert!(
            !raw_disk.contains("5000000000"),
            "Amounts must NOT appear in cleartext"
        );
        assert!(
            !raw_disk.contains("\"b1\""),
            "Blindings must NOT appear in cleartext"
        );

        // Exact single match
        let sel10 = select_notes_for_unshield(&notes_file, 10_000_000_000).unwrap();
        assert_eq!(sel10.len(), 1);
        assert_eq!(sel10[0].commitment, "c2");

        // Combination match: 15 STELL = 5 + 10
        let sel15 = select_notes_for_unshield(&notes_file, 15_000_000_000).unwrap();
        assert_eq!(sel15.len(), 2);
        assert_eq!(sel15.iter().map(|n| n.amount).sum::<u64>(), 15_000_000_000);

        // Mark spent
        mark_notes_spent(&notes_file, &["c2".to_string()]).unwrap();
        let unspent = get_unspent_notes(&notes_file).unwrap();
        assert_eq!(unspent.len(), 2);
        assert_eq!(calculate_shielded_balance(&unspent), 25_000_000_000);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_hardened_notes_store_encryption_decryption_and_tampering() {
        let n = ShieldedNote {
            commitment: "comm_test_123".to_string(),
            amount: 7_777_000_000,
            blinding: "blind_test_456".to_string(),
            height: 42,
            spent: false,
        };
        let notes = vec![n.clone()];

        // 1. Password-based encryption
        let password = "NotesPassword#2026";
        let store = HardenedNotesStore::encrypt(&notes, password).expect("Encrypt password");
        assert_eq!(store.cipher, "XChaCha20-Poly1305");

        let decrypted = store.decrypt(password).expect("Decrypt password");
        assert_eq!(decrypted, notes);

        // Wrong password fails
        assert!(store.decrypt("WrongPassword").is_err());

        // Tampered ciphertext fails Poly1305 MAC
        let mut tampered = store.clone();
        let mut ct = hex::decode(&tampered.ciphertext_hex).unwrap();
        ct[0] ^= 0xFF;
        tampered.ciphertext_hex = hex::encode(ct);
        assert!(tampered.decrypt(password).is_err());

        // Tampered auth tag fails
        let mut tampered_tag = store.clone();
        let mut tag = hex::decode(&tampered_tag.auth_tag_hex).unwrap();
        tag[0] ^= 0x01;
        tampered_tag.auth_tag_hex = hex::encode(tag);
        assert!(tampered_tag.decrypt(password).is_err());

        // 2. Secret-based encryption
        let secret = [0x55u8; 32];
        let secret_store =
            HardenedNotesStore::encrypt_with_secret(&notes, &secret).expect("Encrypt secret");
        let secret_decrypted = secret_store
            .decrypt_with_secret(&secret)
            .expect("Decrypt secret");
        assert_eq!(secret_decrypted, notes);

        // Wrong secret fails
        let wrong_secret = [0x66u8; 32];
        assert!(secret_store.decrypt_with_secret(&wrong_secret).is_err());
    }

    #[test]
    fn test_deterministic_blinding_derivation() {
        let seed = [0x42u8; 32];

        // Derivation is 100% deterministic
        let b0_a = derive_blinding_factor(&seed, 0);
        let b0_b = derive_blinding_factor(&seed, 0);
        assert_eq!(b0_a, b0_b);

        // Different note counter yields different blinding factor
        let b1 = derive_blinding_factor(&seed, 1);
        assert_ne!(b0_a, b1);

        // Canonical curve25519 scalar verification
        use curve25519_dalek::scalar::Scalar;
        assert!(Scalar::from_canonical_bytes(b0_a).into_option().is_some());
        assert!(Scalar::from_canonical_bytes(b1).into_option().is_some());
    }

    #[test]
    fn test_atomic_save_file_scheme_and_permissions() {
        let temp_dir =
            std::env::temp_dir().join(format!("stell_atomic_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let target = temp_dir.join("atomic_notes.json");

        let payload = b"{\"hello\": \"world\"}";
        atomic_save_file(&target, payload).expect("atomic save");

        assert!(target.exists());
        let read_back = fs::read(&target).expect("read");
        assert_eq!(read_back, payload);

        // No lingering .tmp file
        let tmp_file = temp_dir.join("atomic_notes.json.tmp");
        assert!(!tmp_file.exists(), ".tmp file must be cleanly renamed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Must have 0600 permissions");
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_legacy_plaintext_notes_migration_and_compatibility() {
        let temp_dir = std::env::temp_dir().join(format!(
            "stell_legacy_migration_test_{}",
            rand::random::<u64>()
        ));
        let _ = fs::create_dir_all(&temp_dir);
        let notes_file = temp_dir.join("shielded_notes.json");

        let legacy_notes = vec![
            ShieldedNote {
                commitment: "legacy_c1".to_string(),
                amount: 12_345_000_000,
                blinding: "legacy_b1".to_string(),
                height: 100,
                spent: false,
            },
            ShieldedNote {
                commitment: "legacy_c2".to_string(),
                amount: 67_890_000_000,
                blinding: "legacy_b2".to_string(),
                height: 101,
                spent: true,
            },
        ];

        // 1. Write legacy plain JSON (unencrypted) to disk
        let legacy_json = serde_json::to_string_pretty(&legacy_notes).unwrap();
        fs::write(&notes_file, legacy_json.as_bytes()).unwrap();

        // 2. load_notes gracefully reads legacy unencrypted JSON
        let loaded = load_notes(&notes_file).expect("Must load legacy unencrypted notes");
        assert_eq!(loaded, legacy_notes);

        // 3. load_notes_with_password gracefully reads legacy unencrypted JSON
        let loaded_pw = load_notes_with_password(&notes_file, "AnyPassword123")
            .expect("Must migrate legacy with password");
        assert_eq!(loaded_pw, legacy_notes);

        // 4. load_notes_with_secret gracefully reads legacy unencrypted JSON
        let secret = [0x77u8; 32];
        let loaded_sec =
            load_notes_with_secret(&notes_file, &secret).expect("Must migrate legacy with secret");
        assert_eq!(loaded_sec, legacy_notes);

        // 5. Encrypt with password and save
        save_notes_with_password(&notes_file, &legacy_notes, "SecretPass#2026")
            .expect("Save with password");

        let raw_disk = fs::read_to_string(&notes_file).unwrap();
        assert!(raw_disk.contains("XChaCha20-Poly1305"));
        assert!(
            !raw_disk.contains("12345000000"),
            "Amounts must NOT appear in cleartext"
        );
        assert!(
            !raw_disk.contains("legacy_b1"),
            "Blinding must NOT appear in cleartext"
        );

        // Decrypt with correct password
        let decrypted_pw = load_notes_with_password(&notes_file, "SecretPass#2026").unwrap();
        assert_eq!(decrypted_pw, legacy_notes);

        // Wrong password fails
        assert!(load_notes_with_password(&notes_file, "WrongPassword").is_err());

        // 6. Encrypt with secret and save
        save_notes_with_secret(&notes_file, &legacy_notes, &secret).expect("Save with secret");
        let decrypted_sec = load_notes_with_secret(&notes_file, &secret).unwrap();
        assert_eq!(decrypted_sec, legacy_notes);

        // Wrong secret fails
        let wrong_secret = [0x88u8; 32];
        assert!(load_notes_with_secret(&notes_file, &wrong_secret).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
