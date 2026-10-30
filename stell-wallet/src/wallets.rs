//! Multi-Wallet Management Engine for Stellereum Light Wallet
//!
//! Provides secure multi-wallet isolation, named vaults, active wallet switching
//! with Argon2id + XChaCha20Poly1305 password verification, and seamless synchronization
//! with legacy `wallet.json` for backwards compatibility.

use crate::security::{enforce_strict_permissions, HardenedKeystore};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Sanitizes wallet name to prevent directory traversal or invalid characters.
pub fn sanitize_wallet_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Wallet name cannot be empty".to_string());
    }
    if trimmed.len() > 32 {
        return Err("Wallet name cannot exceed 32 characters".to_string());
    }
    if trimmed == "." || trimmed == ".." {
        return Err("Reserved wallet name".to_string());
    }
    for ch in trimmed.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' {
            return Err(format!(
                "Invalid character '{}' in wallet name. Only letters, numbers, hyphens, and underscores are allowed.",
                ch
            ));
        }
    }
    Ok(trimmed.to_string())
}

/// Directory holding all named wallet vaults: `~/.stellereum/wallets/`
pub fn wallets_dir(base_dir: Option<&Path>) -> PathBuf {
    match base_dir {
        Some(dir) => dir.join("wallets"),
        None => stellereum::wallet::default_wallet_dir().join("wallets"),
    }
}

/// File pointing to the currently active wallet name: `~/.stellereum/active_wallet`
pub fn active_wallet_pointer_path(base_dir: Option<&Path>) -> PathBuf {
    match base_dir {
        Some(dir) => dir.join("active_wallet"),
        None => stellereum::wallet::default_wallet_dir().join("active_wallet"),
    }
}

/// Legacy default wallet path: `~/.stellereum/wallet.json`
pub fn legacy_wallet_path(base_dir: Option<&Path>) -> PathBuf {
    match base_dir {
        Some(dir) => dir.join("wallet.json"),
        None => stellereum::wallet::default_wallet_path(),
    }
}

/// Returns the currently active wallet name, if recorded.
pub fn get_active_wallet_name(base_dir: Option<&Path>) -> Option<String> {
    let ptr = active_wallet_pointer_path(base_dir);
    if ptr.exists() {
        if let Ok(content) = fs::read_to_string(&ptr) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                // Audit B-WALLET-3: the pointer file is writable without going
                // through `set_active_wallet_name` — sanitize on READ too, or
                // `/tmp/pwn` / `../evil` payloads escape `wallets/` via join.
                // Invalid content = no active wallet (fall through to default).
                return sanitize_wallet_name(trimmed).ok();
            }
        }
    }
    None
}

/// Sets the currently active wallet name in `~/.stellereum/active_wallet`.
pub fn set_active_wallet_name(name: &str, base_dir: Option<&Path>) -> Result<(), String> {
    let sanitized = sanitize_wallet_name(name)?;
    let ptr = active_wallet_pointer_path(base_dir);
    if let Some(parent) = ptr.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create parent dir: {e}"))?;
        enforce_strict_permissions(parent);
    }

    let tmp = ptr.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("Failed to create active_wallet file: {e}"))?;
        f.write_all(sanitized.as_bytes())
            .map_err(|e| format!("Failed to write active_wallet: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("Failed to sync active_wallet: {e}"))?;
    }
    fs::rename(&tmp, &ptr).map_err(|e| format!("Failed to update active_wallet: {e}"))?;
    enforce_strict_permissions(&ptr);
    Ok(())
}

/// Information about a discovered wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletEntry {
    pub name: String,
    pub address_hex: String,
    pub scheme: String,
    pub is_active: bool,
    pub path: PathBuf,
    pub pq_pubkey_len: Option<usize>,
}

/// Migrates a legacy `wallet.json` into `wallets/default.json` if needed.
fn maybe_migrate_legacy(base_dir: Option<&Path>) {
    let legacy = legacy_wallet_path(base_dir);
    let wdir = wallets_dir(base_dir);

    // Only migrate if legacy wallet exists AND wallets directory does not yet contain any wallets
    if legacy.exists() {
        let has_any_named = if wdir.exists() {
            fs::read_dir(&wdir)
                .map(|r| {
                    r.filter_map(|e| e.ok())
                        .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
                })
                .unwrap_or(false)
        } else {
            false
        };

        if !has_any_named {
            let default_named = wdir.join("default.json");
            if let Ok(ks) = HardenedKeystore::load(&legacy) {
                let _ = fs::create_dir_all(&wdir);
                enforce_strict_permissions(&wdir);
                if ks.save(&default_named).is_ok() {
                    let _ = set_active_wallet_name("default", base_dir);
                }
            }
        }
    }
}

/// Resolves the absolute path to the active wallet file.
///
/// Priority:
/// 1. Explicit CLI argument override (`--wallet <path>`)
/// 2. `STELL_WALLET` environment variable (path or name)
/// 3. Recorded active wallet from `~/.stellereum/active_wallet`
/// 4. `~/.stellereum/wallets/default.json`
/// 5. Fallback `~/.stellereum/wallet.json`
pub fn resolve_active_wallet_path(
    cli_override: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> PathBuf {
    if let Some(p) = cli_override {
        return p;
    }

    maybe_migrate_legacy(base_dir);

    if let Ok(env_target) = std::env::var("STELL_WALLET") {
        let trimmed = env_target.trim();
        if !trimmed.is_empty() {
            let as_path = PathBuf::from(trimmed);
            if as_path.exists() {
                // Explicit operator-chosen path (their own env): honored.
                return as_path;
            }
            // Audit B-WALLET-3: sanitize the name branch like the pointer.
            if let Ok(name) = sanitize_wallet_name(trimmed) {
                let named_path = wallets_dir(base_dir).join(format!("{name}.json"));
                if named_path.exists() {
                    return named_path;
                }
            }
        }
    }

    if let Some(active_name) = get_active_wallet_name(base_dir) {
        let active_path = wallets_dir(base_dir).join(format!("{active_name}.json"));
        if active_path.exists() {
            return active_path;
        }
    }

    let default_named = wallets_dir(base_dir).join("default.json");
    if default_named.exists() {
        return default_named;
    }

    legacy_wallet_path(base_dir)
}

/// Lists all available wallets with metadata and indicates which is currently active.
pub fn list_wallets(base_dir: Option<&Path>) -> Result<Vec<WalletEntry>, String> {
    maybe_migrate_legacy(base_dir);

    let wdir = wallets_dir(base_dir);
    if !wdir.exists() {
        // If neither wallets directory nor legacy wallet exists, return empty list
        let legacy = legacy_wallet_path(base_dir);
        if legacy.exists() {
            if let Ok(ks) = HardenedKeystore::load(&legacy) {
                return Ok(vec![WalletEntry {
                    name: "default".to_string(),
                    address_hex: ks.address_hex.clone(),
                    scheme: ks.scheme.clone(),
                    is_active: true,
                    path: legacy,
                    pq_pubkey_len: ks.pq_pubkey_hex.as_ref().map(|pk| pk.len() / 2),
                }]);
            }
        }
        return Ok(Vec::new());
    }

    enforce_strict_permissions(&wdir);
    let active_name = get_active_wallet_name(base_dir);

    let mut entries = Vec::new();
    let read_dir = fs::read_dir(&wdir).map_err(|e| format!("Failed to read wallets dir: {e}"))?;

    for item in read_dir {
        let item = match item {
            Ok(i) => i,
            Err(_) => continue,
        };
        let path = item.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Ok(ks) = HardenedKeystore::load(&path) {
                    let is_active = match &active_name {
                        Some(act) => act == stem,
                        None => stem == "default",
                    };
                    entries.push(WalletEntry {
                        name: stem.to_string(),
                        address_hex: ks.address_hex.clone(),
                        scheme: ks.scheme.clone(),
                        is_active,
                        path: path.clone(),
                        pq_pubkey_len: ks.pq_pubkey_hex.as_ref().map(|pk| pk.len() / 2),
                    });
                }
            }
        }
    }

    // Sort: active wallet first, then alphabetically by name
    entries.sort_by(|a, b| {
        b.is_active
            .cmp(&a.is_active)
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(entries)
}

/// Switches the active wallet to `name_or_address` after verifying ownership via password.
pub fn switch_wallet(
    name_or_address: &str,
    password: &str,
    base_dir: Option<&Path>,
) -> Result<WalletEntry, String> {
    let all = list_wallets(base_dir)?;
    if all.is_empty() {
        return Err("No wallets found. Create one with 'stell new' first.".to_string());
    }

    let target = name_or_address.trim().to_lowercase();
    let target_unprefixed = target.strip_prefix("inf1:").unwrap_or(&target);
    let parsed_target_addr = stellereum::address::parse_address(name_or_address.trim()).ok();

    let matched = all.iter().find(|w| {
        if w.name.to_lowercase() == target
            || w.address_hex.to_lowercase() == target
            || w.address_hex.to_lowercase() == target_unprefixed
            || w.address_hex.to_lowercase().starts_with(target_unprefixed)
        {
            return true;
        }
        if let Some(target_bytes) = parsed_target_addr {
            if let Ok(w_bytes) = hex::decode(&w.address_hex) {
                if w_bytes == target_bytes {
                    return true;
                }
            }
        }
        false
    });

    let entry = match matched {
        Some(e) => e.clone(),
        None => {
            return Err(format!(
                "Wallet '{}' not found. Run 'stell wallets' to view all available wallets.",
                name_or_address
            ));
        }
    };

    // Load keystore and verify password via decryption
    let keystore = HardenedKeystore::load(&entry.path)
        .map_err(|e| format!("Failed to read wallet vault: {e}"))?;

    let _secret = keystore.decrypt(password).map_err(|_| {
        "Access denied: incorrect password! Active wallet was NOT changed.".to_string()
    })?;

    // Password verified! Set as active wallet
    set_active_wallet_name(&entry.name, base_dir)?;

    // Synchronize legacy `wallet.json` with this active keystore for seamless backward compatibility
    let legacy = legacy_wallet_path(base_dir);
    let _ = keystore.save(&legacy);

    let mut result = entry;
    result.is_active = true;
    Ok(result)
}

/// Saves a newly created or restored keystore under a designated name,
/// marks it as the active wallet, and synchronizes legacy `wallet.json`.
pub fn save_named_wallet(
    name: &str,
    keystore: &HardenedKeystore,
    base_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let sanitized = sanitize_wallet_name(name)?;
    let wdir = wallets_dir(base_dir);
    fs::create_dir_all(&wdir).map_err(|e| format!("Failed to create wallets dir: {e}"))?;
    enforce_strict_permissions(&wdir);

    let target_path = wdir.join(format!("{sanitized}.json"));
    keystore.save(&target_path)?;

    set_active_wallet_name(&sanitized, base_dir)?;

    // Keep legacy path in sync
    let legacy = legacy_wallet_path(base_dir);
    let _ = keystore.save(&legacy);

    Ok(target_path)
}

/// Generates a default name for a new wallet if none was explicitly provided.
pub fn generate_next_wallet_name(base_dir: Option<&Path>) -> String {
    let wdir = wallets_dir(base_dir);
    if !wdir.join("default.json").exists() && !legacy_wallet_path(base_dir).exists() {
        return "default".to_string();
    }

    let mut idx = 2;
    loop {
        let candidate = format!("wallet_{idx}");
        if !wdir.join(format!("{candidate}.json")).exists() {
            return candidate;
        }
        idx += 1;
    }
}
