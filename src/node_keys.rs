//! Node key security hardening: Argon2id + XChaCha20-Poly1305 encryption
//! and strict file/directory permission enforcement (0600 / 0700).
//!
//! # Storage policy — private keys are ENCRYPTED AT REST BY DEFAULT
//!
//! * A **newly generated** node key is written as `enc2:<salt>:<nonce>:<ct>`
//!   (Argon2id 64 MiB / t=3 / p=4 + XChaCha20-Poly1305). The passphrase comes
//!   from the environment: `STELL_KEY_PASSPHRASE`, `STELL_NODE_PASSPHRASE` or
//!   `INFNODE_KEY_PASSPHRASE` (first non-empty wins).
//! * If **no passphrase is available the write is REFUSED** (fail-closed). The
//!   node never leaves a plaintext private key on disk by accident.
//! * Operators who *deliberately* want plaintext opt out explicitly with
//!   `STELL_KEY_PLAINTEXT=1`.
//! * An **existing plaintext key still loads** (backward compatibility with
//!   the keys already sitting on live nodes) and is transparently re-encrypted
//!   in place as soon as a passphrase is available.
//! * An **encrypted key without a passphrase is a hard error**: the node
//!   refuses to start instead of falling back to a plaintext or freshly
//!   generated key.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Primary passphrase environment variable (historic name, kept first so that
/// existing deployments keep working unchanged).
pub const ENV_PASSPHRASE: &str = "STELL_NODE_PASSPHRASE";
/// Preferred passphrase environment variable for the key-storage policy.
pub const ENV_PASSPHRASE_ALT: &str = "STELL_KEY_PASSPHRASE";
/// Legacy fallback passphrase environment variable.
pub const FALLBACK_ENV_PASSPHRASE: &str = "INFNODE_KEY_PASSPHRASE";
/// Explicit operator opt-out: allow writing node keys in plaintext.
pub const ENV_PLAINTEXT: &str = "STELL_KEY_PLAINTEXT";
/// Opt-in interactive passphrase prompt (only used when stdin is a TTY).
pub const ENV_PROMPT: &str = "STELL_KEY_PROMPT";

const KDF_MEM_KIB: u32 = 65_536;
const KDF_ITERS: u32 = 3;
const KDF_LANES: u32 = 4;

/// Help text appended to every "no passphrase" error so that the operator
/// always learns the two supported ways out (supply a passphrase, or
/// explicitly ask for plaintext).
fn passphrase_help() -> String {
    format!(
        "Set {alt} (or {primary}) to a passphrase.\n\
         To deliberately store this key in plaintext, set {plain}=1 (explicit operator opt-out \
         — the key file is then readable by anyone who can read the file).",
        alt = ENV_PASSPHRASE_ALT,
        primary = ENV_PASSPHRASE,
        plain = ENV_PLAINTEXT,
    )
}

/// Resolve passphrase from `STELL_NODE_PASSPHRASE`, then `STELL_KEY_PASSPHRASE`,
/// falling back to `INFNODE_KEY_PASSPHRASE`.
///
/// SECRET HYGIENE: the returned `String` holds key material on the heap.
/// Callers MUST wrap it in [`Zeroizing`] immediately and never log, print,
/// or include it in errors (all load/save paths below do this).
pub fn get_passphrase() -> Option<String> {
    for var in [ENV_PASSPHRASE, ENV_PASSPHRASE_ALT, FALLBACK_ENV_PASSPHRASE] {
        if let Ok(p) = std::env::var(var) {
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    None
}

/// True when the operator explicitly asked for plaintext key files
/// (`STELL_KEY_PLAINTEXT=1|true|yes|on`). Any other value keeps the
/// encrypted-at-rest default.
pub fn plaintext_keys_allowed() -> bool {
    std::env::var(ENV_PLAINTEXT)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// True when the on-disk blob is in an encrypted format (`enc2:` or legacy `enc:`).
pub fn is_encrypted_blob(raw: &[u8]) -> bool {
    match std::str::from_utf8(raw) {
        Ok(text) => {
            let t = text.trim();
            t.starts_with("enc2:") || t.starts_with("enc:")
        }
        Err(_) => false,
    }
}

/// Derive a 32-byte symmetric key from a passphrase and salt using Argon2id.
///
/// Returns the key wrapped in [`Zeroizing`] so the KDF output buffer is
/// wiped on drop: callers never hold a bare `[u8; 32]` copy on the stack.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(KDF_MEM_KIB, KDF_ITERS, KDF_LANES, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!("argon2 kdf: {e}"))?;
    Ok(key)
}

/// Verify that directory exists, is not a symbolic link, and on Unix has strict 0700 permissions.
pub fn verify_dir_perms(dir: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| anyhow!("keystore directory {}: {e}", dir.display()))?;
    if meta.file_type().is_symlink() {
        bail!("keystore directory {} is a symbolic link", dir.display());
    }
    if !meta.is_dir() {
        bail!("path {} is not a directory", dir.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            bail!(
                "keystore directory {} has insecure permissions 0o{:03o}, expected 0o700 (owner-only)",
                dir.display(),
                mode
            );
        }
    }
    Ok(())
}

/// Verify that file exists, is not a symbolic link, and on Unix has strict 0600 permissions.
pub fn verify_file_perms(file: &Path) -> Result<()> {
    let meta =
        std::fs::symlink_metadata(file).map_err(|e| anyhow!("key file {}: {e}", file.display()))?;
    if meta.file_type().is_symlink() {
        bail!("key file {} is a symbolic link", file.display());
    }
    if !meta.is_file() {
        bail!("key path {} is not a file", file.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "key file {} has insecure permissions 0o{:03o}, expected 0o600 (owner-only)",
                file.display(),
                mode
            );
        }
    }
    Ok(())
}

/// Ensure directory exists with 0700 permissions and is not a symbolic link.
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() {
            bail!("keystore directory {} is a symbolic link", dir.display());
        }
    }
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
/// On Unix the file is created with mode 0600 AND re-chmodded to 0600 on the
/// open file descriptor before closing, preventing symlink overwrite and TOCTOU races.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!("key path {} is a symbolic link", path.display());
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(contents)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// Force a file to the private 0600 mode (no-op on non-unix).
///
/// Used for the copies this crate makes of key material (e.g. the rotation
/// backup of `falcon.key`), which must never be world-readable.
pub fn set_private_file_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Encrypt raw bytes with Argon2id + XChaCha20-Poly1305 using passphrase.
/// Output format: `enc2:<salt_hex>:<nonce_hex>:<ct_hex>`.
pub fn encrypt_bytes(data: &[u8], passphrase: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut key = derive_key(passphrase, &salt)?;
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
///
/// FAIL-CLOSED: an encrypted blob without a passphrase is an error — the caller
/// must never silently continue with a plaintext or default key.
pub fn decrypt_bytes(raw: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok();
    if let Some(s) = text {
        let s_trimmed = s.trim();
        if let Some(rest) = s_trimmed.strip_prefix("enc2:") {
            let pass = passphrase.ok_or_else(|| {
                anyhow!(
                    "node key is encrypted (enc2: Argon2id + XChaCha20-Poly1305) but no passphrase \
                     is available.\nThe node refuses to start without it: it will not fall back to \
                     a plaintext or default key.\n{}",
                    passphrase_help()
                )
            })?;
            let parts: Vec<&str> = rest.splitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("bad enc2 blob");
            }
            let salt = hex::decode(parts[0]).map_err(|e| anyhow!("invalid salt hex: {e}"))?;
            let nonce = hex::decode(parts[1]).map_err(|e| anyhow!("invalid nonce hex: {e}"))?;
            let ct = hex::decode(parts[2]).map_err(|e| anyhow!("invalid ciphertext hex: {e}"))?;
            let mut key = derive_key(pass, &salt)?;
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));
            let plain = cipher
                .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
                .map_err(|_| anyhow!("invalid passphrase for node key"))?;
            key.zeroize();
            return Ok(plain);
        } else if s_trimmed.starts_with("enc:") {
            let _pass = passphrase.ok_or_else(|| {
                anyhow!(
                    "node key is encrypted (legacy enc: blob) but no passphrase is available.\n\
                     The node refuses to start without it: it will not fall back to a plaintext or \
                     default key.\n{}",
                    passphrase_help()
                )
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

    // Plaintext fallback: an existing plaintext key still loads (backward
    // compatibility with the keys already on live nodes). The caller may
    // re-encrypt it in place (see `upgrade_plaintext_key_to_encrypted`).
    if passphrase.is_none() {
        tracing::warn!(
            "no key passphrase in the environment: node key loaded from a PLAINTEXT key file"
        );
        eprintln!(
            "[WARN] no key passphrase in the environment: node key loaded from a PLAINTEXT key file"
        );
    } else {
        tracing::warn!("key passphrase present, but this key file was stored in plaintext on disk");
    }
    Ok(raw.to_vec())
}

/// Read a secret from the controlling terminal with echo disabled.
///
/// Only reachable when `STELL_KEY_PROMPT=1` is set AND stdin is a TTY, so that
/// non-interactive daemons (systemd, CI) never block on a prompt.
fn read_secret_from_tty(prompt: &str) -> Option<String> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let no_echo = stty(&["-echo"]);
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if no_echo {
        let _ = stty(&["echo"]);
    }
    eprintln!();
    read.ok()?;
    let value = line.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Run `stty` on the inherited stdin (no external crates needed).
fn stty(args: &[&str]) -> bool {
    std::process::Command::new("stty")
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Optional interactive passphrase prompt (opt-in via `STELL_KEY_PROMPT=1`).
pub fn prompt_passphrase(prompt: &str) -> Option<String> {
    let enabled = std::env::var(ENV_PROMPT)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    read_secret_from_tty(prompt)
}

/// Resolve the passphrase used to WRITE a key file.
///
/// Fails closed when no passphrase is available: writing a plaintext private
/// key by accident is exactly what the encrypted-at-rest default prevents.
fn passphrase_for_write(what: &str) -> Result<Zeroizing<String>> {
    if let Some(p) = get_passphrase() {
        return Ok(Zeroizing::new(p));
    }
    if let Some(p) = prompt_passphrase(&format!("Passphrase for {what}: ")) {
        return Ok(Zeroizing::new(p));
    }
    bail!(
        "refusing to write {what} without encryption: no passphrase is available.\n\
         Node private keys are encrypted at rest by default (enc2: Argon2id + XChaCha20-Poly1305).\n\
         {}",
        passphrase_help()
    )
}

/// Atomically replace `path` with `contents` (0600): same-directory temp file
/// + `rename(2)`, so a crash mid-write can never truncate the live key.
///
/// DURABILITY (audit W6.7): the temp file is `fsync`ed BEFORE the rename and
/// the parent directory is `fsync`ed AFTER it. Without the two syncs a power
/// loss can leave the renamed file present but EMPTY (its data blocks were
/// never flushed) or leave the rename itself unpersisted — the node can come
/// back with a truncated or missing private key. The rename is already atomic
/// for a PROCESS crash; the syncs extend that guarantee to a MACHINE crash.
fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut suffix = [0u8; 6];
    OsRng.fill_bytes(&mut suffix);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "key".to_string());
    let tmp = dir.join(format!(
        ".{}.{}.{}",
        name,
        std::process::id(),
        hex::encode(suffix)
    ));
    write_private_file(&tmp, contents)?;
    // Flush the file's DATA before the rename publishes it.
    if let Err(e) = fsync_path(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("atomic replace of {}: {e}", path.display()));
    }
    // Flush the DIRECTORY entry so the rename itself survives a power loss.
    fsync_path(dir)?;
    Ok(())
}

/// `fsync` a path (a file or a directory). Best-effort on the platforms that
/// refuse it: a failure to sync is reported, but a directory that cannot be
/// opened for reading (some exotic mounts) is not fatal for the write that
/// already succeeded.
fn fsync_path(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let f = std::fs::File::open(path)?;
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Transparently upgrade a plaintext key file to the encrypted `enc2:` format.
///
/// Returns `Ok(true)` when the file was rewritten. Nothing happens (and
/// `Ok(false)` is returned) when the file is already encrypted, when the
/// operator opted out with `STELL_KEY_PLAINTEXT=1`, or when no passphrase is
/// available (a plaintext key must keep working on nodes that have no
/// passphrase configured).
///
/// The upgrade is best-effort: a failure leaves the key readable and is
/// reported as a warning — it never breaks node startup.
fn upgrade_plaintext_key_to_encrypted(path: &Path, raw: &[u8], plain: &[u8]) -> Result<bool> {
    if is_encrypted_blob(raw) {
        return Ok(false);
    }
    if plaintext_keys_allowed() {
        return Ok(false);
    }
    let Some(p) = get_passphrase() else {
        return Ok(false);
    };
    let pass = Zeroizing::new(p);
    let blob = Zeroizing::new(encrypt_bytes(plain, pass.as_str())?);
    atomic_write_private(path, blob.as_bytes())?;
    Ok(true)
}

/// Load Falcon-512 keypair from path, verifying permissions and decrypting if encrypted.
pub fn load_falcon_key(path: &Path) -> Result<crate::post_quantum::FalconKeypair> {
    if let Some(parent) = path.parent() {
        if parent.exists() {
            verify_dir_perms(parent)?;
        }
    }
    verify_file_perms(path)?;
    let raw =
        std::fs::read(path).map_err(|e| anyhow!("read falcon key {}: {e}", path.display()))?;
    let pass = Zeroizing::new(get_passphrase());
    let plain_bytes = Zeroizing::new(decrypt_bytes(&raw, pass.as_deref())?);
    let key = crate::post_quantum::FalconKeypair::from_bytes(&plain_bytes).ok_or_else(|| {
        anyhow!(
            "invalid Falcon-512 key in {}\n\
             The key is corrupt: its private-key components are inconsistent with its public \
             key (the NTRU partner G does not belong to the lattice of h), or the file is \
             truncated. NOTE: a key written before the W4.1 FIPS 206 fix (no NTRU partner G) \
             is NOT rejected here — it is repaired in memory at load time and keeps signing \
             with the SAME validator address; rotate it with `stellereum keys rotate-falcon`.",
            path.display()
        )
    })?;
    // Transparent upgrade of an existing plaintext key file. It runs after the
    // key has been parsed, so a corrupt file is reported as invalid instead
    // of being encrypted first.
    match upgrade_plaintext_key_to_encrypted(path, &raw, plain_bytes.as_slice()) {
        Ok(true) => {
            tracing::info!("upgraded {} to the encrypted enc2: format", path.display());
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(
                "could not re-encrypt {} in place: {e} (key left as-is, still usable)",
                path.display()
            );
            eprintln!(
                "[WARN] could not re-encrypt {} in place: {e} (key left as-is, still usable)",
                path.display()
            );
        }
    }
    Ok(key)
}

/// Save Falcon-512 keypair to path with strict permissions (0600 file, 0700 dir).
///
/// ENCRYPTED BY DEFAULT: the key is written as `enc2:` (Argon2id +
/// XChaCha20-Poly1305) using the passphrase from the environment. If no
/// passphrase is available the write is REFUSED unless the operator explicitly
/// set `STELL_KEY_PLAINTEXT=1`.
///
/// ATOMIC (audit W6.7): the file is written through a same-directory temp
/// file + `rename(2)` (see [`atomic_write_private`]), so a crash mid-write can
/// never leave a TRUNCATED key file — the old in-place truncate could, and a
/// truncated validator key is an unrecoverable identity loss.
pub fn save_falcon_key(path: &Path, key: &crate::post_quantum::FalconKeypair) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_secure_dir(parent)?;
    }
    let key_bytes = Zeroizing::new(key.to_bytes());
    let content: Zeroizing<Vec<u8>> = if plaintext_keys_allowed() {
        tracing::warn!(
            "{}={} set: saving falcon.key in PLAINTEXT",
            ENV_PLAINTEXT,
            std::env::var(ENV_PLAINTEXT).unwrap_or_default()
        );
        eprintln!("[WARN] {}=1: saving falcon.key in PLAINTEXT", ENV_PLAINTEXT);
        Zeroizing::new(key_bytes.to_vec())
    } else {
        let pass = passphrase_for_write("falcon.key")?;
        Zeroizing::new(encrypt_bytes(&key_bytes, pass.as_str())?.into_bytes())
    };
    atomic_write_private(path, &content)
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
/// Ed25519 identity seed and the ML-KEM-768 seed in process heap. There is
/// no PFS claim on the KEM channel: a heap disclosure (core dump, swap,
/// `/proc/<pid>/mem`) exposes both long-term secrets. Operators MUST disable
/// core dumps and encrypted-swap-or-no-swap on validators; treat the KEM
/// seed as long-lived (no forward secrecy) in the threat model. What this
/// function DOES guarantee: 0700/0600 enforcement fail-closed, Argon2id
/// decryption with wrong-passphrase rejection, `Zeroizing` for every
/// transient buffer up to the (un-wipeable) return value.
///
/// FULL-PQ: `e2e.key` carries the 64-byte KEM seed (hex). A legacy 32-byte
/// X25519 `e2e.key` is REFUSED loudly (wipe — never silently accepted as KEM
/// material, same rule as `infnode::keyring::NodeKeys::load`).
///
/// A plaintext key file still loads (backward compatibility with the keys
/// already on live nodes) and is transparently re-encrypted in place when a
/// passphrase is available. An encrypted key file without a passphrase is a
/// hard error: the node must not start with a fallback identity.
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

    // Transparent upgrade: plaintext key files are re-encrypted in place as
    // soon as a passphrase is available (best-effort, never fatal). It runs
    // AFTER the key material has been parsed and validated, so a corrupt
    // file is reported as such instead of being encrypted first.
    let id_str = std::str::from_utf8(&id_plain)?.trim();
    let e2e_str = std::str::from_utf8(&e2e_plain)?.trim();

    let id_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        hex::decode(id_str)
            .map_err(|e| anyhow!("identity key hex: {e}"))?
            .try_into()
            .map_err(|_| anyhow!("identity seed must be 32 bytes"))?,
    );
    let e2e_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        hex::decode(e2e_str).map_err(|e| anyhow!("e2e key hex: {e}"))?,
    );
    if e2e_bytes.len() == 32 {
        // Wipe-compat: a 32-byte seed is the pre-PQ X25519 static secret —
        // refused loudly, never silently accepted as KEM material.
        anyhow::bail!(
            "e2e.key: legacy x25519 key refused (FULL-PQ wipe: delete e2e.key and restart to generate a KEM key)"
        );
    }
    let kem_seed: [u8; infnode::mailbox::KEM_SEED_LEN] = e2e_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("e2e kem seed must be 64 bytes"))?;
    let kem_ek = infnode::mailbox::kem_ek_from_seed(&kem_seed);

    for (path, raw, plain) in [
        (&id_path, &id_raw, &id_plain),
        (&e2e_path, &e2e_raw, &e2e_plain),
    ] {
        match upgrade_plaintext_key_to_encrypted(path, raw, plain.as_slice()) {
            Ok(true) => {
                tracing::info!("upgraded {} to the encrypted enc2: format", path.display());
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    "could not re-encrypt {} in place: {e} (key left as-is, still usable)",
                    path.display()
                );
                eprintln!(
                    "[WARN] could not re-encrypt {} in place: {e} (key left as-is, still usable)",
                    path.display()
                );
            }
        }
    }

    let signing = ed25519_dalek::SigningKey::from_bytes(&id_bytes);
    let verifying = signing.verifying_key();

    Ok(infnode::keyring::NodeKeys {
        signing,
        verifying,
        kem_seed,
        kem_ek,
    })
}

/// Save infnode NodeKeys (identity.key and e2e.key) with 0700 dir and 0600 files.
///
/// ENCRYPTED BY DEFAULT: both files are written as `enc2:` (Argon2id +
/// XChaCha20-Poly1305) using the passphrase from the environment. If no
/// passphrase is available the write is REFUSED unless the operator explicitly
/// set `STELL_KEY_PLAINTEXT=1`.
///
/// ATOMIC (audit W6.7): both files are written through a same-directory temp
/// file + `rename(2)` (see [`atomic_write_private`]). The old in-place
/// truncate could leave a TRUNCATED key file if the process died mid-write —
/// and a truncated identity seed is an unrecoverable identity loss (the node
/// would come back with a DIFFERENT identity, or refuse to start).
pub fn save_node_keys(dir: &Path, keys: &infnode::keyring::NodeKeys) -> Result<()> {
    ensure_secure_dir(dir)?;
    let id_hex = Zeroizing::new(hex::encode(keys.signing.to_bytes()));
    let e2e_hex = Zeroizing::new(hex::encode(keys.kem_seed));

    let (id_blob, e2e_blob): (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) = if plaintext_keys_allowed()
    {
        tracing::warn!(
            "{} set: saving node keys in PLAINTEXT",
            std::env::var(ENV_PLAINTEXT).unwrap_or_default()
        );
        eprintln!("[WARN] {}=1: saving node keys in PLAINTEXT", ENV_PLAINTEXT);
        (
            Zeroizing::new(id_hex.as_bytes().to_vec()),
            Zeroizing::new(e2e_hex.as_bytes().to_vec()),
        )
    } else {
        let pass = passphrase_for_write("node keys")?;
        (
            Zeroizing::new(encrypt_bytes(id_hex.as_bytes(), pass.as_str())?.into_bytes()),
            Zeroizing::new(encrypt_bytes(e2e_hex.as_bytes(), pass.as_str())?.into_bytes()),
        )
    };

    atomic_write_private(&dir.join("identity.key"), id_blob.as_slice())?;
    atomic_write_private(&dir.join("e2e.key"), e2e_blob.as_slice())?;
    Ok(())
}

/// Load or generate and save infnode NodeKeys.
///
/// FAIL-CLOSED: an existing but undecryptable key is an error — the node never
/// falls back to a freshly generated identity. A brand-new key is written
/// encrypted (or refused, when no passphrase is available).
pub fn load_or_generate_node_keys(dir: &Path) -> Result<infnode::keyring::NodeKeys> {
    if dir.join("identity.key").exists() {
        load_node_keys(dir)
    } else {
        let k = infnode::keyring::NodeKeys::generate();
        save_node_keys(dir, &k)?;
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Env vars touched by the policy; saved/restored around every test.
    const ENV_VARS: &[&str] = &[
        ENV_PASSPHRASE,
        ENV_PASSPHRASE_ALT,
        FALLBACK_ENV_PASSPHRASE,
        ENV_PLAINTEXT,
        ENV_PROMPT,
    ];

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Clears every passphrase/plaintext env var and restores the previous
    /// values when the guard is dropped.
    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            let saved = ENV_VARS
                .iter()
                .map(|v| ((*v).to_string(), std::env::var(v).ok()))
                .collect();
            for v in ENV_VARS {
                std::env::remove_var(v);
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (var, value) in self.saved.drain(..) {
                match value {
                    Some(v) => std::env::set_var(&var, v),
                    None => std::env::remove_var(&var),
                }
            }
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "stell_node_keys_{tag}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn write_plaintext_key(path: &Path, contents: &[u8]) {
        write_private_file(path, contents).unwrap();
    }

    /// generate -> encrypt -> decrypt round-trip (the `enc2:` format itself).
    #[test]
    fn enc2_encrypt_decrypt_roundtrip() {
        let _g = env_lock();
        let secret = b"node-private-seed-material-0123456789abcdef";
        let blob = encrypt_bytes(secret, "correct-horse-battery-staple").unwrap();
        assert!(blob.starts_with("enc2:"), "must use the enc2: format");
        assert_eq!(blob.split(':').count(), 4, "enc2: salt:nonce:ct");
        assert!(
            !blob.contains("node-private-seed-material"),
            "ciphertext must not leak the plaintext"
        );

        let plain = decrypt_bytes(blob.as_bytes(), Some("correct-horse-battery-staple")).unwrap();
        assert_eq!(plain, secret);

        // Wrong passphrase is rejected.
        let err = decrypt_bytes(blob.as_bytes(), Some("wrong-passphrase")).unwrap_err();
        assert!(
            err.to_string().contains("passphrase"),
            "error must mention the passphrase: {err}"
        );

        // Missing passphrase fails closed (no silent plaintext fallback).
        let err = decrypt_bytes(blob.as_bytes(), None).unwrap_err();
        assert!(
            err.to_string().contains("encrypted"),
            "error must say the key is encrypted: {err}"
        );
        assert!(
            err.to_string().contains(ENV_PASSPHRASE_ALT),
            "error must document the passphrase env var: {err}"
        );
    }

    /// A newly generated node key is written ENCRYPTED by default.
    #[test]
    fn generated_node_keys_are_encrypted_by_default() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE_ALT, "generated-key-passphrase");

        let dir = temp_dir("gen_enc");
        let keys = load_or_generate_node_keys(&dir).expect("generate node keys");
        let pub_bytes = keys.signing.verifying_key().to_bytes();
        let id_hex = hex::encode(keys.signing.to_bytes());

        let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
        assert!(raw.starts_with("enc2:"), "identity.key must be enc2:");
        assert!(
            !raw.contains(&id_hex),
            "identity.key must not leak the seed"
        );

        let raw_e2e = std::fs::read_to_string(dir.join("e2e.key")).unwrap();
        assert!(raw_e2e.starts_with("enc2:"), "e2e.key must be enc2:");

        // And it round-trips through the loader.
        let reloaded = load_node_keys(&dir).expect("reload encrypted node keys");
        assert_eq!(reloaded.signing.verifying_key().to_bytes(), pub_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The alt env var name from the runbook works as well.
    #[test]
    fn passphrase_env_alias_is_honoured() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE_ALT, "alias-passphrase");
        assert_eq!(get_passphrase().as_deref(), Some("alias-passphrase"));

        let dir = temp_dir("alias");
        let keys = load_or_generate_node_keys(&dir).expect("generate with alias env var");
        let pub_bytes = keys.signing.verifying_key().to_bytes();
        let reloaded = load_node_keys(&dir).expect("reload");
        assert_eq!(reloaded.signing.verifying_key().to_bytes(), pub_bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a passphrase the node must NOT write a plaintext key.
    #[test]
    fn missing_passphrase_refuses_to_write_new_key() {
        let _g = env_lock();
        let _env = EnvGuard::new();

        let dir = temp_dir("no_pass");
        let err = match load_or_generate_node_keys(&dir) {
            Err(e) => e,
            Ok(_) => panic!("must refuse without a passphrase"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(ENV_PASSPHRASE_ALT) || msg.contains(ENV_PASSPHRASE),
            "error must document the passphrase env var: {msg}"
        );
        assert!(
            msg.contains(ENV_PLAINTEXT),
            "error must document the plaintext escape hatch: {msg}"
        );
        assert!(
            !dir.join("identity.key").exists(),
            "no key file may be written when the write is refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An encrypted key without a passphrase fails closed (no fallback key).
    #[test]
    fn encrypted_key_without_passphrase_fails_closed() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE, "temp-passphrase");

        let dir = temp_dir("fail_closed");
        let keys = load_or_generate_node_keys(&dir).expect("generate encrypted keys");
        let pub_bytes = keys.signing.verifying_key().to_bytes();

        // Passphrase disappears (e.g. systemd unit without the env file).
        std::env::remove_var(ENV_PASSPHRASE);
        let err = match load_node_keys(&dir) {
            Err(e) => e,
            Ok(_) => panic!("must fail closed"),
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("encrypted"), "error must say encrypted: {msg}");
        assert!(
            msg.contains(ENV_PASSPHRASE_ALT),
            "error must document the passphrase env var: {msg}"
        );
        // load_or_generate must not silently generate a NEW identity.
        let err = match load_or_generate_node_keys(&dir) {
            Err(e) => e,
            Ok(_) => panic!("must fail closed"),
        };
        assert!(format!("{err:#}").contains("encrypted"));
        // The key file on disk is untouched and still encrypted.
        let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
        assert!(raw.starts_with("enc2:"), "key file must stay encrypted");

        // With the passphrase back, the same identity is returned.
        std::env::set_var(ENV_PASSPHRASE, "temp-passphrase");
        let reloaded = load_node_keys(&dir).expect("reload with passphrase");
        assert_eq!(reloaded.signing.verifying_key().to_bytes(), pub_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Existing PLAINTEXT keys keep loading, and are transparently
    /// re-encrypted in place once a passphrase is available. (FULL-PQ: this
    /// covers 64-byte KEM-seed plaintext; a legacy 32-byte X25519 plaintext
    /// is refused — see `legacy_x25519_e2e_key_is_refused_loudly`.)
    #[test]
    fn plaintext_key_still_loads_and_is_upgraded() {
        let _g = env_lock();
        let _env = EnvGuard::new();

        let dir = temp_dir("plain_compat");
        let keys = infnode::keyring::NodeKeys::generate();
        let pub_bytes = keys.signing.verifying_key().to_bytes();
        let id_hex = hex::encode(keys.signing.to_bytes());
        let e2e_hex = hex::encode(keys.kem_seed);

        // Exactly what the live nodes have on disk: raw hex, 0600.
        write_plaintext_key(&dir.join("identity.key"), id_hex.as_bytes());
        write_plaintext_key(&dir.join("e2e.key"), e2e_hex.as_bytes());

        // No passphrase: the plaintext key still loads (backward compatibility).
        let loaded = load_node_keys(&dir).expect("plaintext key must still load");
        assert_eq!(loaded.signing.verifying_key().to_bytes(), pub_bytes);
        let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
        assert!(
            !raw.starts_with("enc2:"),
            "without a passphrase the file must be left alone"
        );

        // With a passphrase: transparent in-place upgrade to enc2:.
        std::env::set_var(ENV_PASSPHRASE, "upgrade-passphrase");
        let loaded = load_node_keys(&dir).expect("plaintext key must load and be upgraded");
        assert_eq!(loaded.signing.verifying_key().to_bytes(), pub_bytes);
        let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
        assert!(raw.starts_with("enc2:"), "key must be upgraded to enc2:");
        assert!(
            !raw.contains(&id_hex),
            "upgraded key must not leak the seed"
        );
        let raw_e2e = std::fs::read_to_string(dir.join("e2e.key")).unwrap();
        assert!(
            raw_e2e.starts_with("enc2:"),
            "e2e key must be upgraded to enc2:"
        );

        // And it still loads as the very same identity.
        let reloaded = load_node_keys(&dir).expect("reload upgraded key");
        assert_eq!(reloaded.signing.verifying_key().to_bytes(), pub_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FULL-PQ wipe: a legacy 32-byte X25519 `e2e.key` (exactly what the
    /// pre-PQ nodes have on disk) is REFUSED loudly — never silently
    /// accepted as KEM material. The operator deletes the file and restarts
    /// to generate a KEM key.
    #[test]
    fn legacy_x25519_e2e_key_is_refused_loudly() {
        let _g = env_lock();
        let _env = EnvGuard::new();

        let dir = temp_dir("legacy_refuse");
        let keys = infnode::keyring::NodeKeys::generate();
        let id_hex = hex::encode(keys.signing.to_bytes());
        write_plaintext_key(&dir.join("identity.key"), id_hex.as_bytes());
        // Pre-PQ shape: 32-byte X25519 static secret, raw hex.
        write_plaintext_key(&dir.join("e2e.key"), hex::encode([0x77u8; 32]).as_bytes());

        let err = match load_node_keys(&dir) {
            Err(e) => e,
            Ok(_) => panic!("legacy x25519 e2e.key must be refused"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("legacy x25519 key refused"),
            "refusal must name the cause, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The KEM seed round-trips through save/load and the encapsulation key
    /// is re-derived deterministically from it (never stored).
    #[test]
    fn kem_seed_roundtrips_and_ek_is_derived() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE, "kem-roundtrip");

        let dir = temp_dir("kem_rt");
        let keys = infnode::keyring::NodeKeys::generate();
        save_node_keys(&dir, &keys).expect("save KEM keys");
        let loaded = load_node_keys(&dir).expect("reload KEM keys");
        assert_eq!(loaded.kem_seed, keys.kem_seed, "KEM seed must round-trip");
        assert_eq!(
            loaded.kem_ek,
            infnode::mailbox::kem_ek_from_seed(&keys.kem_seed),
            "ek must re-derive from the seed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The explicit escape hatch writes (and keeps) plaintext keys.
    #[test]
    fn plaintext_env_override_works() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PLAINTEXT, "1");

        let dir = temp_dir("plain_opt");
        let keys = infnode::keyring::NodeKeys::generate();
        let id_hex = hex::encode(keys.signing.to_bytes());
        let pub_bytes = keys.signing.verifying_key().to_bytes();

        save_node_keys(&dir, &keys).expect("save with plaintext override");
        let raw = std::fs::read_to_string(dir.join("identity.key")).unwrap();
        assert!(
            !raw.starts_with("enc2:"),
            "plaintext override must not encrypt"
        );
        assert!(
            raw.contains(&id_hex),
            "plaintext override must write raw hex"
        );

        // And it loads back.
        let loaded = load_node_keys(&dir).expect("load plaintext key");
        assert_eq!(loaded.signing.verifying_key().to_bytes(), pub_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The escape hatch must not become a decryption bypass.
    #[test]
    fn plaintext_override_does_not_decrypt_encrypted_keys() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE, "encrypted-passphrase");

        let dir = temp_dir("override_bypass");
        load_or_generate_node_keys(&dir).expect("generate encrypted keys");

        std::env::remove_var(ENV_PASSPHRASE);
        std::env::set_var(ENV_PLAINTEXT, "1");
        let err = match load_node_keys(&dir) {
            Err(e) => e,
            Ok(_) => panic!("must not decrypt without a passphrase"),
        };
        assert!(format!("{err:#}").contains("encrypted"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The falcon key follows the same policy.
    #[test]
    fn falcon_key_is_encrypted_by_default() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE, "falcon-passphrase");

        let dir = temp_dir("falcon_enc");
        let path = dir.join("falcon.key");
        let fk = crate::post_quantum::FalconKeypair::generate();
        let pub_key = fk.public_key.clone();

        save_falcon_key(&path, &fk).expect("save encrypted falcon key");
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(b"enc2:"), "falcon key must be enc2:");

        let loaded = load_falcon_key(&path).expect("load encrypted falcon key");
        assert_eq!(loaded.public_key, pub_key);

        // Without a passphrase it fails closed.
        std::env::remove_var(ENV_PASSPHRASE);
        let err = load_falcon_key(&path).expect_err("must fail closed");
        assert!(format!("{err:#}").contains("encrypted"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // ATOMICITY / DURABILITY / PERMISSIONS (audit W6.7)
    // -----------------------------------------------------------------------

    /// The atomic write replaces the CONTENT in one step and never leaves the
    /// target truncated: the file mode stays 0600 and the bytes are exactly
    /// what was written.
    #[test]
    fn atomic_write_private_replaces_content_and_keeps_0600() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        let dir = temp_dir("atomic_write");
        let path = dir.join("identity.key");
        write_plaintext_key(&path, b"OLD-CONTENT");

        atomic_write_private(&path, b"NEW-CONTENT").expect("atomic write");
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW-CONTENT");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the atomic write must keep 0600, got {mode:o}");
        }
        // No temp file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".identity.key"))
            .collect();
        assert!(leftovers.is_empty(), "the temp file must be renamed away");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FAILED atomic write leaves the previous content intact — the
    /// "crash mid-migration must not lose the key" contract. The failure is
    /// provoked by pointing the target at a DIRECTORY: `rename(2)` refuses,
    /// and the original file must be untouched (and the temp file cleaned up).
    #[test]
    fn failed_atomic_write_leaves_the_previous_key_intact() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        let dir = temp_dir("atomic_fail");
        let target = dir.join("target");
        std::fs::create_dir_all(&target).unwrap();

        let err = atomic_write_private(&target, b"NEW").expect_err("must fail");
        assert!(format!("{err:#}").contains("atomic replace"));
        // The target is still the directory it was — nothing was clobbered.
        assert!(
            target.is_dir(),
            "the failed write must not clobber the target"
        );
        // And no temp file is left in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".target"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed write must clean up its temp file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The transparent plaintext -> enc2 migration is a WHOLE-FILE replace:
    /// the file is either the old plaintext or the new ciphertext, never a
    /// mix, and the identity it carries is byte-identical afterwards.
    #[test]
    fn plaintext_to_encrypted_migration_is_a_whole_file_replace() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE, "migrate-passphrase");

        let dir = temp_dir("migrate");
        let keys = infnode::keyring::NodeKeys::generate();
        let pub_bytes = keys.signing.verifying_key().to_bytes();
        let id_hex = hex::encode(keys.signing.to_bytes());
        let e2e_hex = hex::encode(keys.kem_seed);
        write_plaintext_key(&dir.join("identity.key"), id_hex.as_bytes());
        write_plaintext_key(&dir.join("e2e.key"), e2e_hex.as_bytes());

        let loaded = load_node_keys(&dir).expect("load + migrate");
        assert_eq!(loaded.signing.verifying_key().to_bytes(), pub_bytes);

        for f in ["identity.key", "e2e.key"] {
            let raw = std::fs::read_to_string(dir.join(f)).unwrap();
            assert!(raw.starts_with("enc2:"), "{f} must be fully migrated");
            assert!(raw.contains(':'), "{f} must carry the salt/nonce/ct fields");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::symlink_metadata(dir.join(f))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(
                    mode, 0o600,
                    "{f} must stay 0600 after the migration, got {mode:o}"
                );
            }
            // No temp file survived the migration.
            let leftovers: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
                .collect();
            assert!(
                leftovers.is_empty(),
                "the migration left a temp file behind"
            );
        }

        // And the migrated identity still loads.
        let reloaded = load_node_keys(&dir).expect("reload migrated keys");
        assert_eq!(reloaded.signing.verifying_key().to_bytes(), pub_bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The KDF salt is stored WITH the ciphertext and is fresh per
    /// encryption: two blobs of the same plaintext under the same passphrase
    /// differ, so the ciphertext is not a deterministic function of the
    /// passphrase alone (an attacker cannot precompute a rainbow table over
    /// the stored blob).
    #[test]
    fn kdf_salt_is_stored_with_the_ciphertext_and_is_random() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        let secret = b"the-same-secret-material";
        let a = encrypt_bytes(secret, "same-passphrase").unwrap();
        let b = encrypt_bytes(secret, "same-passphrase").unwrap();
        assert_ne!(a, b, "two encryptions must not be byte-identical");
        let salt_a = a.split(':').nth(1).unwrap();
        let salt_b = b.split(':').nth(1).unwrap();
        assert_ne!(salt_a, salt_b, "the KDF salt must be random per encryption");
        assert_eq!(salt_a.len(), 32, "the salt is 16 bytes, hex-encoded");
        // Both decrypt with the same passphrase.
        assert_eq!(
            decrypt_bytes(a.as_bytes(), Some("same-passphrase")).unwrap(),
            secret
        );
        assert_eq!(
            decrypt_bytes(b.as_bytes(), Some("same-passphrase")).unwrap(),
            secret
        );
    }

    /// A world-readable key file is REFUSED (fail-closed on the mode).
    #[test]
    fn insecure_key_file_mode_is_refused() {
        let _g = env_lock();
        let _env = EnvGuard::new();
        std::env::set_var(ENV_PASSPHRASE, "perms-passphrase");

        let dir = temp_dir("perms");
        let keys = infnode::keyring::NodeKeys::generate();
        let id_hex = hex::encode(keys.signing.to_bytes());
        let e2e_hex = hex::encode(keys.kem_seed);
        write_plaintext_key(&dir.join("identity.key"), id_hex.as_bytes());
        write_plaintext_key(&dir.join("e2e.key"), e2e_hex.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.join("identity.key"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let err = match load_node_keys(&dir) {
            Err(e) => e,
            Ok(_) => panic!("a 0644 key file must be refused"),
        };
        assert!(
            format!("{err:#}").contains("0o644") || format!("{err:#}").contains("insecure"),
            "the error must name the insecure mode: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
