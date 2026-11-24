use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SNAPSHOT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const SHA256_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SHA256_MANIFEST_BYTES: usize = 4096;

pub(crate) struct StoreBootstrapOptions {
    pub data_dir: PathBuf,
    pub keys_dir: PathBuf,
    pub shard: u32,
    pub snapshot_url: String,
    pub sha256_url: Option<String>,
    pub require_sha256: bool,
    pub archive: Option<PathBuf>,
    pub expected_sha256: Option<String>,
    pub refresh_if_stale: bool,
    pub force: bool,
    pub no_backup: bool,
    pub i_fenced_all_signers: bool,
    pub observer: bool,
    pub dry_run: bool,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sha256Plan {
    Pinned(String),
    Url(String),
    Disabled,
}

#[derive(Debug, Serialize)]
struct StoreBootstrapReport {
    ok: bool,
    dry_run: bool,
    mode: String,
    data_dir: String,
    store_dir: String,
    keys_dir: Option<String>,
    shard: u32,
    source: SourceReport,
    sha256: Sha256Report,
    replaced_existing: bool,
    backup_path: Option<String>,
    snap_files_removed: usize,
    safety_reset: SafetyResetReport,
    safety_init: SafetyInitReport,
}

#[derive(Debug, Serialize)]
struct SourceReport {
    kind: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct Sha256Report {
    status: String,
    actual: Option<String>,
    expected: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Serialize)]
struct SafetyResetReport {
    ran: bool,
    removed_existing_record: bool,
}

#[derive(Debug, Serialize)]
struct SafetyInitReport {
    ran: bool,
    validator: Option<String>,
    shard: Option<u32>,
    generation: Option<u64>,
    height: Option<u64>,
    finalized_height: Option<u64>,
}

struct TempDirGuard {
    path: PathBuf,
    armed: bool,
}

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn run_store_bootstrap(opts: StoreBootstrapOptions) -> Result<()> {
    if !opts.observer && !opts.i_fenced_all_signers {
        bail!(
            "refusing store bootstrap: pass --i-fenced-all-signers ONLY after stopping and \
             fencing all legacy validators and remote signers for this key, or pass --observer \
             to bootstrap an observer without initializing a validator safety record"
        );
    }

    let pinned_sha256 = opts
        .expected_sha256
        .as_deref()
        .map(normalize_sha256_hex)
        .transpose()?;

    let sha256_plan = resolve_sha256_plan(&opts, pinned_sha256)?;

    if let Some(ref archive_path) = opts.archive {
        if !archive_path.exists() || !archive_path.is_file() {
            bail!(
                "archive path does not exist or is not a regular file: {}",
                archive_path.display()
            );
        }
    } else {
        let url = opts.snapshot_url.trim();
        if url.is_empty() || (!url.starts_with("http://") && !url.starts_with("https://")) {
            bail!(
                "invalid --snapshot-url '{}': expected http:// or https:// URL (or pass --archive)",
                opts.snapshot_url
            );
        }
    }

    let store_dir = opts.data_dir.join("store");
    let store_exists = store_dir.exists();
    let replace_allowed = opts.refresh_if_stale || opts.force;
    if store_exists && !replace_allowed {
        bail!(
            "refusing store bootstrap: existing store found at {}; pass --refresh-if-stale or \
             --force to back up and replace it (nothing changed)",
            store_dir.display()
        );
    }

    if !opts.observer {
        let key_path = opts.keys_dir.join("validator.key");
        let legacy_path = opts.keys_dir.join("identity.key");
        if !key_path.exists() && !legacy_path.exists() {
            bail!(
                "keys directory {} must contain validator.key (or identity.key) for validator \
                 store bootstrap; pass --observer to bootstrap an observer without validator keys",
                opts.keys_dir.display()
            );
        }
    }

    let ts = utc_timestamp_compact();
    let planned_backup = if store_exists && !opts.no_backup {
        Some(unique_backup_path(&opts.data_dir, "store", &ts))
    } else {
        None
    };

    let mode_str = if opts.observer {
        "observer"
    } else {
        "validator"
    };
    let source_report = match &opts.archive {
        Some(p) => SourceReport {
            kind: "archive".to_string(),
            value: p.display().to_string(),
        },
        None => SourceReport {
            kind: "url".to_string(),
            value: opts.snapshot_url.clone(),
        },
    };

    if opts.dry_run {
        let (expected_pin, sha_url, sha_status) = match &sha256_plan {
            Sha256Plan::Pinned(hex_str) => (Some(hex_str.clone()), None, "planned_pinned"),
            Sha256Plan::Url(u) => (None, Some(u.clone()), "planned_url"),
            Sha256Plan::Disabled => (None, None, "skipped"),
        };
        let report = StoreBootstrapReport {
            ok: true,
            dry_run: true,
            mode: mode_str.to_string(),
            data_dir: opts.data_dir.display().to_string(),
            store_dir: store_dir.display().to_string(),
            keys_dir: if opts.observer {
                None
            } else {
                Some(opts.keys_dir.display().to_string())
            },
            shard: opts.shard,
            source: source_report,
            sha256: Sha256Report {
                status: sha_status.to_string(),
                actual: None,
                expected: expected_pin,
                url: sha_url,
            },
            replaced_existing: store_exists,
            backup_path: planned_backup.map(|p| p.display().to_string()),
            snap_files_removed: 0,
            safety_reset: SafetyResetReport {
                ran: false,
                removed_existing_record: false,
            },
            safety_init: SafetyInitReport {
                ran: false,
                validator: None,
                shard: if opts.observer {
                    None
                } else {
                    Some(opts.shard)
                },
                generation: None,
                height: None,
                finalized_height: None,
            },
        };
        emit_report(&report, opts.json);
        return Ok(());
    }

    // Check database locks BEFORE downloading, extracting, or mutating anything.
    ensure_data_dir_stores_unlocked(&opts.data_dir)?;

    // In validator mode, validate/decrypt the consensus key BEFORE mutating disk.
    let val_pub = if opts.observer {
        None
    } else {
        Some(crate::cli::handlers::resolve_consensus_validator_pubkey(
            &opts.keys_dir,
            None,
        )?)
    };

    // Temp workspace in system temp dir for download (so failed downloads never touch data_dir).
    let work_dir = std::env::temp_dir().join(format!(
        "stell-store-bootstrap-{}-{}",
        std::process::id(),
        unix_nanos()
    ));
    fs::create_dir_all(&work_dir)
        .with_context(|| format!("create temporary work dir {}", work_dir.display()))?;
    let _work_guard = TempDirGuard::new(work_dir.clone());

    let archive_path = match &opts.archive {
        Some(local) => local.clone(),
        None => {
            let downloaded = work_dir.join("snapshot.tar.zst");
            eprintln!(
                "[store-bootstrap] downloading snapshot from {}...",
                opts.snapshot_url
            );
            download_snapshot(&opts.snapshot_url, &downloaded)?;
            downloaded
        }
    };

    // Verify SHA-256 BEFORE extracting or touching existing store.
    let actual_sha256 = sha256_file(&archive_path)?;
    let sha_report = verify_sha256_against_plan(&actual_sha256, &sha256_plan, opts.require_sha256)?;

    // Validate archive entries (path-traversal check) BEFORE mutating data_dir.
    let entries = inspect_tar_zst_entries(&archive_path)?;
    if entries.is_empty() {
        bail!("snapshot archive {} is empty", archive_path.display());
    }

    // Create data_dir if missing (track cleanup on failure prior to commit).
    let data_dir_preexisted = opts.data_dir.exists();
    if !data_dir_preexisted {
        fs::create_dir_all(&opts.data_dir)
            .with_context(|| format!("create data dir {}", opts.data_dir.display()))?;
    }
    let mut data_dir_guard = TempDirGuard::new(opts.data_dir.clone());
    if data_dir_preexisted {
        data_dir_guard.disarm();
    }
    set_dir_mode_0700(&opts.data_dir)?;

    // Stage extraction inside data_dir so final move into place is an atomic rename.
    let staging_dir = opts.data_dir.join(format!(
        ".bootstrap-staging-{}-{}",
        std::process::id(),
        unix_nanos()
    ));
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("create staging dir {}", staging_dir.display()))?;
    let _staging_guard = TempDirGuard::new(staging_dir.clone());

    extract_tar_zst(&archive_path, &staging_dir)?;
    normalize_extracted_layout(&staging_dir)?;
    let snap_files_removed = strip_stale_snap_files(&staging_dir)?;

    // Re-check sled locks right before replacing existing store(s).
    ensure_data_dir_stores_unlocked(&opts.data_dir)?;

    let mut backup_path_used: Option<PathBuf> = None;
    if store_dir.exists() {
        if opts.no_backup {
            fs::remove_dir_all(&store_dir)
                .with_context(|| format!("remove existing store {}", store_dir.display()))?;
        } else {
            let bp = unique_backup_path(&opts.data_dir, "store", &ts);
            fs::rename(&store_dir, &bp).with_context(|| {
                format!(
                    "backup existing store {} -> {}",
                    store_dir.display(),
                    bp.display()
                )
            })?;
            backup_path_used = Some(bp);
        }
    }

    // Move staged store (and any store-shard* / snapshot entries) into data_dir.
    commit_staged_entries(&staging_dir, &opts.data_dir, &ts, opts.no_backup)?;
    data_dir_guard.disarm();

    // Run safety-reset (+ safety-init unless --observer) using the exact CLI/library helpers.
    let storage =
        stellereum::storage::Storage::open(&store_dir).with_context(
            || match &backup_path_used {
                Some(bp) => format!(
                    "open bootstrapped store {} (previous store backup preserved at {})",
                    store_dir.display(),
                    bp.display()
                ),
                None => format!("open bootstrapped store {}", store_dir.display()),
            },
        )?;

    let removed_existing_record = crate::cli::handlers::run_safety_reset_on_storage(&storage)
        .with_context(|| match &backup_path_used {
            Some(bp) => format!(
                "safety-reset failed on {} (previous store backup preserved at {})",
                store_dir.display(),
                bp.display()
            ),
            None => format!("safety-reset failed on {}", store_dir.display()),
        })?;

    let safety_init_report = if let Some(pk) = val_pub {
        let (record, payload) = crate::cli::handlers::run_safety_init_on_storage(
            &storage,
            pk,
            opts.shard,
            None,
            None,
            opts.i_fenced_all_signers,
        )
        .with_context(|| match &backup_path_used {
            Some(bp) => format!(
                "safety-init failed on {} (previous store backup preserved at {})",
                store_dir.display(),
                bp.display()
            ),
            None => format!("safety-init failed on {}", store_dir.display()),
        })?;
        SafetyInitReport {
            ran: true,
            validator: Some(hex::encode(pk)),
            shard: Some(opts.shard),
            generation: Some(record.generation),
            height: Some(payload.height),
            finalized_height: Some(payload.finalized_height),
        }
    } else {
        SafetyInitReport {
            ran: false,
            validator: None,
            shard: None,
            generation: None,
            height: None,
            finalized_height: None,
        }
    };
    drop(storage);

    let report = StoreBootstrapReport {
        ok: true,
        dry_run: false,
        mode: mode_str.to_string(),
        data_dir: opts.data_dir.display().to_string(),
        store_dir: store_dir.display().to_string(),
        keys_dir: if opts.observer {
            None
        } else {
            Some(opts.keys_dir.display().to_string())
        },
        shard: opts.shard,
        source: source_report,
        sha256: sha_report,
        replaced_existing: store_exists,
        backup_path: backup_path_used.map(|p| p.display().to_string()),
        snap_files_removed,
        safety_reset: SafetyResetReport {
            ran: true,
            removed_existing_record,
        },
        safety_init: safety_init_report,
    };
    emit_report(&report, opts.json);
    Ok(())
}

fn resolve_sha256_plan(opts: &StoreBootstrapOptions, pinned: Option<String>) -> Result<Sha256Plan> {
    if let Some(pin) = pinned {
        return Ok(Sha256Plan::Pinned(pin));
    }
    if let Some(ref url) = opts.sha256_url {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            if opts.require_sha256 {
                bail!("--require-sha256 cannot be used with an empty --sha256-url");
            }
            return Ok(Sha256Plan::Disabled);
        }
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            bail!("invalid --sha256-url '{trimmed}': expected http:// or https:// URL");
        }
        return Ok(Sha256Plan::Url(trimmed.to_string()));
    }
    if opts.archive.is_some() {
        if opts.require_sha256 {
            bail!(
                "--require-sha256 set with --archive, but neither --expected-sha256 nor \
                 --sha256-url was provided"
            );
        }
        return Ok(Sha256Plan::Disabled);
    }
    Ok(Sha256Plan::Url(format!(
        "{}.sha256",
        opts.snapshot_url.trim()
    )))
}

fn normalize_sha256_hex(raw: &str) -> Result<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid SHA-256 digest '{raw}': expected 64 hexadecimal characters");
    }
    Ok(normalized)
}

fn parse_sha256_manifest_text(text: &str) -> Result<String> {
    let first = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("empty SHA-256 manifest response"))?;
    normalize_sha256_hex(first)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("open {} for sha256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn download_snapshot(url: &str, dest: &Path) -> Result<()> {
    let resp = ureq::get(url)
        .timeout(SNAPSHOT_DOWNLOAD_TIMEOUT)
        .call()
        .map_err(|e| anyhow!("failed to download snapshot from {url}: {e}"))?;
    let mut reader = resp.into_reader();
    let mut out = fs::File::create(dest)
        .with_context(|| format!("create staging archive {}", dest.display()))?;
    std::io::copy(&mut reader, &mut out)
        .with_context(|| format!("write downloaded snapshot to {}", dest.display()))?;
    out.flush()?;
    Ok(())
}

enum Sha256FetchOutcome {
    Digest(String),
    NotFound,
    Unavailable(String),
}

fn fetch_sha256_manifest(url: &str) -> Result<Sha256FetchOutcome> {
    match ureq::get(url).timeout(SHA256_FETCH_TIMEOUT).call() {
        Ok(resp) => {
            let mut reader = resp
                .into_reader()
                .take((MAX_SHA256_MANIFEST_BYTES + 1) as u64);
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf)?;
            if buf.len() > MAX_SHA256_MANIFEST_BYTES {
                bail!("SHA-256 manifest at {url} exceeded {MAX_SHA256_MANIFEST_BYTES} bytes");
            }
            let text = String::from_utf8(buf)
                .map_err(|e| anyhow!("SHA-256 manifest at {url} is not valid UTF-8: {e}"))?;
            let digest = parse_sha256_manifest_text(&text)
                .with_context(|| format!("invalid SHA-256 manifest format at {url}"))?;
            Ok(Sha256FetchOutcome::Digest(digest))
        }
        Err(ureq::Error::Status(404, _)) => Ok(Sha256FetchOutcome::NotFound),
        Err(e) => Ok(Sha256FetchOutcome::Unavailable(e.to_string())),
    }
}

fn verify_sha256_against_plan(
    actual: &str,
    plan: &Sha256Plan,
    require_sha256: bool,
) -> Result<Sha256Report> {
    match plan {
        Sha256Plan::Pinned(expected) => {
            if actual != expected {
                bail!("snapshot SHA-256 mismatch: expected={expected} actual={actual}");
            }
            Ok(Sha256Report {
                status: "verified".to_string(),
                actual: Some(actual.to_string()),
                expected: Some(expected.clone()),
                url: None,
            })
        }
        Sha256Plan::Url(url) => match fetch_sha256_manifest(url)? {
            Sha256FetchOutcome::Digest(expected) => {
                if actual != expected {
                    bail!("snapshot SHA-256 mismatch: expected={expected} actual={actual}");
                }
                Ok(Sha256Report {
                    status: "verified".to_string(),
                    actual: Some(actual.to_string()),
                    expected: Some(expected),
                    url: Some(url.clone()),
                })
            }
            Sha256FetchOutcome::NotFound => {
                if require_sha256 {
                    bail!(
                        "SHA-256 manifest returned HTTP 404 at {url} and --require-sha256 is set"
                    );
                }
                eprintln!(
                    "[WARN] SHA-256 manifest returned HTTP 404 at {url}; proceeding without checksum verification"
                );
                Ok(Sha256Report {
                    status: "skipped_unavailable".to_string(),
                    actual: Some(actual.to_string()),
                    expected: None,
                    url: Some(url.clone()),
                })
            }
            Sha256FetchOutcome::Unavailable(err) => {
                if require_sha256 {
                    bail!(
                        "failed to fetch SHA-256 manifest at {url} ({err}) and --require-sha256 is set"
                    );
                }
                eprintln!(
                    "[WARN] could not fetch SHA-256 manifest at {url} ({err}); proceeding without checksum verification"
                );
                Ok(Sha256Report {
                    status: "skipped_unavailable".to_string(),
                    actual: Some(actual.to_string()),
                    expected: None,
                    url: Some(url.clone()),
                })
            }
        },
        Sha256Plan::Disabled => Ok(Sha256Report {
            status: "skipped".to_string(),
            actual: Some(actual.to_string()),
            expected: None,
            url: None,
        }),
    }
}

fn ensure_data_dir_stores_unlocked(data_dir: &Path) -> Result<()> {
    if !data_dir.exists() {
        return Ok(());
    }
    let store_dir = data_dir.join("store");
    ensure_store_unlocked(&store_dir)?;
    for entry in
        fs::read_dir(data_dir).with_context(|| format!("read data dir {}", data_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("store-shard") && entry.file_type()?.is_dir() {
            ensure_store_unlocked(&entry.path())?;
        }
    }
    Ok(())
}

fn ensure_store_unlocked(store_dir: &Path) -> Result<()> {
    if !store_dir.join("db").exists() {
        return Ok(());
    }
    match stellereum::storage::sled_config_for(store_dir).open() {
        Ok(db) => {
            drop(db);
            Ok(())
        }
        Err(e) if is_sled_lock_error(&e) => {
            bail!(
                "refusing to modify {}: sled database lock is held by a running node/process \
                 (stop the node first): {e}",
                store_dir.display()
            );
        }
        Err(_) => Ok(()),
    }
}

fn is_sled_lock_error(err: &sled::Error) -> bool {
    match err {
        sled::Error::Io(io_err) => {
            io_err.kind() == std::io::ErrorKind::WouldBlock
                || io_err.to_string().contains("could not acquire lock")
        }
        _ => err.to_string().contains("could not acquire lock"),
    }
}

fn validate_archive_entry_path(entry: &str) -> Result<()> {
    if entry.is_empty() || entry.contains('\0') {
        bail!("invalid empty or NUL-containing archive entry");
    }
    if entry.starts_with('/') || entry.starts_with('\\') || entry.contains('\\') {
        bail!("refusing unsafe archive entry path '{entry}'");
    }
    for comp in Path::new(entry).components() {
        match comp {
            Component::CurDir | Component::Normal(_) => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("refusing path-traversal archive entry '{entry}'");
            }
        }
    }
    Ok(())
}

fn inspect_tar_zst_entries(archive: &Path) -> Result<Vec<String>> {
    let output = Command::new("tar")
        .arg("-I")
        .arg("zstd")
        .arg("-tf")
        .arg(archive)
        .output()
        .map_err(|e| anyhow!("failed to execute 'tar -I zstd -tf': {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "failed to inspect snapshot archive {}: {}",
            archive.display(),
            stderr.trim()
        );
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| anyhow!("archive listing contains non-UTF-8 paths: {e}"))?;
    let mut entries = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        validate_archive_entry_path(line)?;
        entries.push(line.to_string());
    }
    Ok(entries)
}

fn extract_tar_zst(archive: &Path, dest: &Path) -> Result<()> {
    let output = Command::new("tar")
        .arg("-I")
        .arg("zstd")
        .arg("--no-same-owner")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .output()
        .map_err(|e| anyhow!("failed to execute 'tar -I zstd -xf': {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "snapshot extraction failed for {}: {}",
            archive.display(),
            stderr.trim()
        );
    }
    reject_symlinks_recursive(dest)?;
    Ok(())
}

fn reject_symlinks_recursive(dir: &Path) -> Result<()> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("scan extracted dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("stat extracted path {}", path.display()))?;
        if meta.file_type().is_symlink() {
            bail!(
                "refusing snapshot archive: unexpected symlink at {}",
                path.display()
            );
        }
        if meta.file_type().is_dir() {
            reject_symlinks_recursive(&path)?;
        }
    }
    Ok(())
}

fn normalize_extracted_layout(staging_dir: &Path) -> Result<()> {
    if staging_dir.join("store").is_dir() {
        return Ok(());
    }
    let nested_data = staging_dir.join("data");
    if nested_data.join("store").is_dir() {
        for entry in fs::read_dir(&nested_data)? {
            let entry = entry?;
            let src = entry.path();
            let dst = staging_dir.join(entry.file_name());
            if dst.exists() {
                bail!(
                    "cannot normalize nested data/ layout: destination {} already exists",
                    dst.display()
                );
            }
            fs::rename(&src, &dst)?;
        }
        let _ = fs::remove_dir(&nested_data);
    }
    if !staging_dir.join("store").is_dir() {
        bail!(
            "extracted snapshot archive does not contain a 'store/' (or 'data/store/') directory"
        );
    }
    Ok(())
}

fn strip_stale_snap_files(root: &Path) -> Result<usize> {
    let mut removed = 0usize;
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if (name_str == "store" || name_str.starts_with("store-shard"))
            && entry.file_type()?.is_dir()
        {
            let store_path = entry.path();
            for item in fs::read_dir(&store_path)
                .with_context(|| format!("scan {} for stale snap* files", store_path.display()))?
            {
                let item = item?;
                let item_name = item.file_name();
                if item_name.to_string_lossy().starts_with("snap") && !item.file_type()?.is_dir() {
                    fs::remove_file(item.path()).with_context(|| {
                        format!("remove stale snap file {}", item.path().display())
                    })?;
                    removed += 1;
                }
            }
        }
    }
    Ok(removed)
}

fn commit_staged_entries(
    staging_dir: &Path,
    data_dir: &Path,
    ts: &str,
    no_backup: bool,
) -> Result<()> {
    for entry in fs::read_dir(staging_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let src = entry.path();
        let dst = data_dir.join(&name);

        if dst.exists() {
            if name_str.starts_with("store-shard") {
                if no_backup {
                    if dst.is_dir() {
                        fs::remove_dir_all(&dst)?;
                    } else {
                        fs::remove_file(&dst)?;
                    }
                } else {
                    let bp = unique_backup_path(data_dir, &name_str, ts);
                    fs::rename(&dst, &bp)?;
                }
            } else if dst.is_dir() {
                fs::remove_dir_all(&dst)?;
            } else {
                fs::remove_file(&dst)?;
            }
        }
        fs::rename(&src, &dst)
            .with_context(|| format!("move staged entry {} -> {}", src.display(), dst.display()))?;
    }
    Ok(())
}

fn unique_backup_path(data_dir: &Path, dir_name: &str, ts: &str) -> PathBuf {
    let base = data_dir.join(format!("{dir_name}.bak-bootstrap-{ts}"));
    if !base.exists() {
        return base;
    }
    let with_pid = data_dir.join(format!(
        "{dir_name}.bak-bootstrap-{ts}.{}",
        std::process::id()
    ));
    if !with_pid.exists() {
        return with_pid;
    }
    let mut idx = 1u64;
    loop {
        let cand = data_dir.join(format!(
            "{dir_name}.bak-bootstrap-{ts}.{}.{}",
            std::process::id(),
            idx
        ));
        if !cand.exists() {
            return cand;
        }
        idx += 1;
    }
}

fn set_dir_mode_0700(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn utc_timestamp_compact() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // Howard Hinnant's civil-from-days algorithm (UTC).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn emit_report(report: &StoreBootstrapReport, json: bool) {
    if json {
        if let Ok(rendered) = serde_json::to_string_pretty(report) {
            println!("{rendered}");
        }
        return;
    }
    if report.dry_run {
        println!("Stellereum store bootstrap (DRY RUN — no disk writes or downloads)");
    } else {
        println!("Stellereum store bootstrap complete");
    }
    println!("  mode        : {}", report.mode);
    println!("  data_dir    : {}", report.data_dir);
    println!("  store_dir   : {}", report.store_dir);
    if let Some(ref kd) = report.keys_dir {
        println!("  keys_dir    : {kd} (shard={})", report.shard);
    }
    println!(
        "  source      : {} ({})",
        report.source.value, report.source.kind
    );
    println!(
        "  sha256      : {} (actual={}, expected={})",
        report.sha256.status,
        report.sha256.actual.as_deref().unwrap_or("<none>"),
        report.sha256.expected.as_deref().unwrap_or("<none>")
    );
    if let Some(ref bp) = report.backup_path {
        println!("  backup_path : {bp}");
    }
    if !report.dry_run {
        println!(
            "  snap_clean  : removed {} snap* file(s)",
            report.snap_files_removed
        );
        println!(
            "  safety_reset: ran={} removed_existing={}",
            report.safety_reset.ran, report.safety_reset.removed_existing_record
        );
        if report.safety_init.ran {
            println!(
                "  safety_init : validator={} shard={} generation={} height={} finalized={}",
                report.safety_init.validator.as_deref().unwrap_or("?"),
                report.safety_init.shard.unwrap_or(0),
                report.safety_init.generation.unwrap_or(0),
                report.safety_init.height.unwrap_or(0),
                report.safety_init.finalized_height.unwrap_or(0)
            );
        } else {
            println!("  safety_init : skipped (observer mode)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_and_manifest_parsing() {
        let digest = "A".repeat(64);
        assert_eq!(normalize_sha256_hex(&digest).unwrap(), "a".repeat(64));
        assert!(normalize_sha256_hex("deadbeef").is_err());
        assert!(normalize_sha256_hex(&"z".repeat(64)).is_err());

        let manifest = format!("  {}  latest.tar.zst\n", "B".repeat(64));
        assert_eq!(
            parse_sha256_manifest_text(&manifest).unwrap(),
            "b".repeat(64)
        );
        assert!(parse_sha256_manifest_text("   ").is_err());
    }

    #[test]
    fn path_traversal_entries_are_rejected() {
        assert!(validate_archive_entry_path("store/db").is_ok());
        assert!(validate_archive_entry_path("./store/conf").is_ok());
        assert!(validate_archive_entry_path("data/store/blobs/1").is_ok());

        assert!(validate_archive_entry_path("").is_err());
        assert!(validate_archive_entry_path("/etc/passwd").is_err());
        assert!(validate_archive_entry_path("../escape").is_err());
        assert!(validate_archive_entry_path("store/../../escape").is_err());
        assert!(validate_archive_entry_path("store\\evil").is_err());
        assert!(validate_archive_entry_path("store/a\0b").is_err());
    }

    #[test]
    fn strip_stale_snap_files_only_removes_snap_prefixed_files() {
        let base = std::env::temp_dir().join(format!(
            "stell-strip-snap-{}-{}",
            std::process::id(),
            unix_nanos()
        ));
        let store = base.join("store");
        let shard1 = base.join("store-shard1");
        let other = base.join("other");
        fs::create_dir_all(&store).unwrap();
        fs::create_dir_all(&shard1).unwrap();
        fs::create_dir_all(&other).unwrap();

        fs::write(store.join("db"), b"db").unwrap();
        fs::write(store.join("snap.0001"), b"s1").unwrap();
        fs::write(store.join("snap.temp"), b"s2").unwrap();
        fs::write(shard1.join("snap.0002"), b"s3").unwrap();
        fs::write(other.join("snap.keep"), b"keep").unwrap();

        let removed = strip_stale_snap_files(&base).unwrap();
        assert_eq!(removed, 3);
        assert!(store.join("db").exists());
        assert!(!store.join("snap.0001").exists());
        assert!(!store.join("snap.temp").exists());
        assert!(!shard1.join("snap.0002").exists());
        assert!(other.join("snap.keep").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn utc_timestamp_format_is_compact_iso() {
        let ts = utc_timestamp_compact();
        assert_eq!(ts.len(), 16);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[8..9], "T");
    }
}
