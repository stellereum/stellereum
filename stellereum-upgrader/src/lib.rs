//! Cosmovisor-like supervisor for a Stellereum coordinated binary upgrade.
//!
//! The halted node already wrote a durable `upgrade-halt.marker` (or the plan
//! is readable from committed governance state over RPC). This crate is the
//! small, auditable operator-side tool that:
//!
//! 1. reads the plan (`name`, `height`, `sha256`) from the marker or from
//!    `stell_governanceParams` (`result.applied.upgrade_plan`);
//! 2. waits for the halt marker (a plan alone is not a halt);
//! 3. verifies the staged binary's SHA-256, refusing a symlink or a
//!    world-writable staged file;
//! 4. atomically replaces the live binary via a same-directory rename of the
//!    EXACT verified bytes;
//! 5. runs the configured restart command and appends each step to a progress
//!    file.
//!
//! Dry-run is the DEFAULT. `--apply` is required to touch the live binary.
//!
//! # Privileges
//!
//! The supervisor never needs root when the live binary, marker and progress
//! file are owned by the service user and the restart command is user-scoped
//! (for example `systemctl --user restart stellereum`, or a small wrapper
//! that invokes the system manager you already use). If it is accidentally
//! started as root it refuses `--apply` unless `--allow-root` is passed, so a
//! root-owned rename cannot happen silently. See `docs/UPGRADE_AND_RECOVERY.md`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// Exact marker header written by the halted node.
pub const MARKER_HEADER: &str = "stell-upgrade-halt v1";

/// Marker field parser is strict on this header; a future format must bump it.
pub const MAX_UPGRADE_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// The committed upgrade plan, in the shape both sources agree on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradePlan {
    /// Target version label (also the staging directory name).
    pub name: String,
    /// Coordinated halt height.
    pub height: u64,
    /// SHA-256 of the target binary.
    pub sha256: [u8; 32],
}

impl UpgradePlan {
    /// Parse the durable marker written by the halted node.
    ///
    /// Unknown `key=value` lines are tolerated (forward compatibility inside
    /// v1); a wrong header, missing required field or bad digest is refused.
    pub fn from_marker(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        match lines.next() {
            Some(first) if first.trim() == MARKER_HEADER => {}
            Some(other) => return Err(format!("bad upgrade-halt marker header: {other:?}")),
            None => return Err("empty upgrade-halt marker".to_string()),
        }
        let mut name: Option<String> = None;
        let mut height: Option<u64> = None;
        let mut sha256: Option<[u8; 32]> = None;
        for raw in lines {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("malformed marker line: {line:?}"));
            };
            match key {
                "plan_name" => {
                    let v = value.trim();
                    if v.is_empty() {
                        return Err("empty marker field 'plan_name'".to_string());
                    }
                    name = Some(v.to_string());
                }
                "height" => {
                    height = Some(
                        value
                            .trim()
                            .parse::<u64>()
                            .map_err(|e| format!("bad marker height: {e}"))?,
                    );
                }
                "plan_sha256" => {
                    let bytes = hex_decode(value.trim())?;
                    let arr: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| "plan_sha256 must be exactly 32 bytes".to_string())?;
                    sha256 = Some(arr);
                }
                _ => {}
            }
        }
        let plan = Self {
            name: name.ok_or_else(|| "missing marker field 'plan_name'".to_string())?,
            height: height.ok_or_else(|| "missing marker field 'height'".to_string())?,
            sha256: sha256.ok_or_else(|| "missing marker field 'plan_sha256'".to_string())?,
        };
        if plan.sha256 == [0u8; 32] {
            return Err("plan_sha256 is all zero; refusing an unverifiable plan".to_string());
        }
        Ok(plan)
    }

    /// Parse `result.applied.upgrade_plan` from `stell_governanceParams`.
    ///
    /// `Ok(None)` means the committed state has no plan yet (a normal answer
    /// before governance executes the proposal) — never a parse failure.
    pub fn from_rpc_value(value: &serde_json::Value) -> Result<Option<Self>, String> {
        if let Some(err) = value.get("error") {
            return Err(format!("RPC error reading the upgrade plan: {err}"));
        }
        let plan = value.pointer("/result/applied/upgrade_plan");
        match plan {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(plan) => {
                let name = plan
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "RPC upgrade plan has no string 'name'".to_string())?
                    .to_string();
                let height = plan
                    .get("height")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| "RPC upgrade plan has no integer 'height'".to_string())?;
                let sha_hex = plan
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "RPC upgrade plan has no string 'sha256'".to_string())?;
                let bytes = hex_decode(sha_hex)?;
                let sha256: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "RPC plan sha256 must be exactly 32 bytes".to_string())?;
                if sha256 == [0u8; 32] {
                    return Err("RPC plan sha256 is all zero; refusing".to_string());
                }
                Ok(Some(Self {
                    name,
                    height,
                    sha256,
                }))
            }
        }
    }

    /// Read the plan from a marker file. `Ok(None)` means "no marker yet".
    pub fn read_marker(path: &Path) -> Result<Option<Self>, String> {
        match fs::read_to_string(path) {
            Ok(text) => Self::from_marker(&text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("read marker {}: {e}", path.display())),
        }
    }

    /// Read the committed plan over JSON-RPC (`stell_governanceParams`).
    pub fn read_rpc(url: &str) -> Result<Option<Self>, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "stell_governanceParams",
            "params": [],
        })
        .to_string();
        let response = ureq::post(url)
            .timeout(Duration::from_secs(5))
            .send_string(&body)
            .map_err(|e| format!("RPC {url}: {e}"))?;
        let value: serde_json::Value = {
            let text = response
                .into_string()
                .map_err(|e| format!("RPC {url}: read body: {e}"))?;
            serde_json::from_str(&text)
                .map_err(|e| format!("RPC {url}: invalid JSON: {e}"))?
        };
        Self::from_rpc_value(&value)
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string has an odd length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("bad hex digit {:?}", b as char)),
    }
}

/// SHA-256 of a byte slice, as lowercase hex (the plan displays this form).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A staged binary whose bytes and digest have already been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBinary {
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
}

/// Verify the staged binary against the plan digest.
///
/// Refusals are all fail-closed:
/// * the path or its parent is a symlink;
/// * the path is not a regular file;
/// * the file is larger than [`MAX_UPGRADE_BINARY_BYTES`];
/// * the file (or any parent of it) is world-writable (`mode & 0o002`),
///   because any local user could then swap the bytes between check and use;
/// * the SHA-256 does not match the plan exactly.
pub fn verify_staged(path: &Path, expected: &[u8; 32]) -> Result<VerifiedBinary, String> {
    if *expected == [0u8; 32] {
        return Err("expected sha256 is all zero; refusing".to_string());
    }
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("staged binary {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "staged binary {} is a SYMLINK; refusing (must be a regular file)",
            path.display()
        ));
    }
    if !meta.is_file() {
        return Err(format!(
            "staged binary {} is not a regular file",
            path.display()
        ));
    }
    if meta.len() > MAX_UPGRADE_BINARY_BYTES {
        return Err(format!(
            "staged binary {} is too large ({} bytes > {MAX_UPGRADE_BINARY_BYTES})",
            path.display(),
            meta.len()
        ));
    }
    check_parent_dir(path, "staged binary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 {
            return Err(format!(
                "staged binary {} is WORLD-WRITABLE (mode {:o}); refusing",
                path.display(),
                mode
            ));
        }
    }
    let bytes =
        fs::read(path).map_err(|e| format!("read staged binary {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_UPGRADE_BINARY_BYTES {
        return Err("staged binary grew past the size cap while reading".to_string());
    }
    let digest = Sha256::digest(&bytes);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest);
    if &sha256 != expected {
        return Err(format!(
            "staged binary {} sha256 mismatch (expected {}, got {})",
            path.display(),
            hex_encode(expected),
            hex_encode(&sha256)
        ));
    }
    Ok(VerifiedBinary { sha256, bytes })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn check_parent_dir(path: &Path, label: &str) -> Result<(), String> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    let meta = fs::symlink_metadata(parent)
        .map_err(|e| format!("{label} {}: parent {}: {e}", path.display(), parent.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{label} {}: parent {} is a SYMLINK; refusing",
            path.display(),
            parent.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!(
            "{label} {}: parent {} is not a directory",
            path.display(),
            parent.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 {
            return Err(format!(
                "{label} {}: parent {} is WORLD-WRITABLE (mode {:o}); refusing",
                path.display(),
                parent.display(),
                mode
            ));
        }
    }
    Ok(())
}

/// Atomically replace `live` with the VERIFIED bytes.
///
/// The temp file is created in the live binary's directory with a fresh name,
/// fsynced, chmod 0755, then renamed over `live`. Renaming a temp file of the
/// same filesystem is atomic: a crash leaves either the old or the new binary,
/// never a half-written one. `dry_run` performs every check but writes nothing.
pub fn atomic_install(live: &Path, verified: &VerifiedBinary, dry_run: bool) -> Result<(), String> {
    match fs::symlink_metadata(live) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "live binary {} is a SYMLINK; refusing to replace its target",
                live.display()
            ));
        }
        Ok(meta) if meta.is_dir() => {
            return Err(format!(
                "live binary {} is a directory, not a file",
                live.display()
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("stat live binary {}: {e}", live.display())),
    }
    check_parent_dir(live, "live binary")?;
    if dry_run {
        return Ok(());
    }
    let parent = live
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = live
        .file_name()
        .ok_or_else(|| format!("live binary {} has no file name", live.display()))?
        .to_string_lossy();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(
        ".{file_name}.upgrade-{}-{nonce}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("create temp {}: {e}", tmp.display()))?;
    let write_all = file
        .write_all(&verified.bytes)
        .map_err(|e| format!("write temp {}: {e}", tmp.display()));
    if let Err(e) = write_all {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let synced = file
        .sync_all()
        .map_err(|e| format!("fsync temp {}: {e}", tmp.display()));
    drop(file);
    if let Err(e) = synced {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)) {
            let _ = fs::remove_file(&tmp);
            return Err(format!("chmod temp {}: {e}", tmp.display()));
        }
    }
    if let Err(e) = fs::rename(&tmp, live) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("rename {} -> {}: {e}", tmp.display(), live.display()));
    }
    sync_dir(parent)
}

fn sync_dir(dir: &Path) -> Result<(), String> {
    File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("fsync directory {}: {e}", dir.display()))
}

/// Run the operator-configured restart command via the shell.
///
/// The command is deliberately a single string: the operator owns it (for
/// example `systemctl --user restart stellereum`). The supervisor never adds
/// privileges.
pub fn run_restart_command(command: &str) -> Result<(), String> {
    if command.trim().is_empty() {
        return Err("restart command is empty".to_string());
    }
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .map_err(|e| format!("run restart command: {e}"))?;
    if !status.success() {
        return Err(format!("restart command exited with {status}"));
    }
    Ok(())
}

/// Append-only progress journal. One line per step, timestamped in epoch
/// seconds, so an operator can prove what the supervisor did and when.
#[derive(Clone, Debug)]
pub struct Progress {
    path: PathBuf,
}

impl Progress {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, step: &str, detail: &str) -> Result<(), String> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create progress dir {}: {e}", parent.display()))?;
        }
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!("unix={unix} step={step} {detail}\n");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open progress {}: {e}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .map_err(|e| format!("write progress {}: {e}", self.path.display()))?;
        file.sync_all()
            .map_err(|e| format!("fsync progress {}: {e}", self.path.display()))?;
        Ok(())
    }
}

/// Block until a marker appears and parses, or the timeout elapses.
///
/// `poll` is clamped to at least 10 ms. A malformed marker is an immediate
/// ERROR: waiting longer cannot repair a torn/mismatched marker.
pub fn wait_for_marker(
    path: &Path,
    timeout: Duration,
    poll: Duration,
) -> Result<UpgradePlan, String> {
    let poll = poll.max(Duration::from_millis(10));
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match UpgradePlan::read_marker(path) {
            Ok(Some(plan)) => return Ok(plan),
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out after {:?} waiting for the halt marker {}",
                timeout,
                path.display()
            ));
        }
        std::thread::sleep(poll.min(deadline - now));
    }
}

/// `true` when the process is running as root (Unix only).
#[cfg(unix)]
pub fn is_root() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "stell-upgrader-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    const SHA: [u8; 32] = [0xab; 32];

    fn marker_text(name: &str, height: u64, sha: &[u8; 32]) -> String {
        format!(
            "{MARKER_HEADER}\nheight={height}\nhalted_at_height={height}\nplan_name={name}\n\
             plan_sha256={}\ntarget_version={name}\nrunning_version=0.1.0\nhalted_unix=1\n",
            hex_encode(sha)
        )
    }

    fn write_exec(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write test binary");
        let mut perms = fs::metadata(path).expect("stat").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod");
    }

    #[test]
    fn marker_plan_parses_and_ignores_forward_compatible_fields() {
        let plan = UpgradePlan::from_marker(&marker_text("v0.2.0", 1200, &SHA)).expect("parse");
        assert_eq!(
            plan,
            UpgradePlan {
                name: "v0.2.0".to_string(),
                height: 1200,
                sha256: SHA,
            }
        );
        let mut extra = marker_text("v0.2.0", 7, &SHA);
        extra.push_str("new_future_field=yes\n");
        assert_eq!(UpgradePlan::from_marker(&extra).expect("forward compat"), plan_with(7));
    }

    fn plan_with(height: u64) -> UpgradePlan {
        UpgradePlan {
            name: "v0.2.0".to_string(),
            height,
            sha256: SHA,
        }
    }

    #[test]
    fn marker_plan_refuses_bad_header_missing_fields_and_zero_digest() {
        assert!(UpgradePlan::from_marker("stell-upgrade-halt v2\n").is_err());
        let no_name: String = marker_text("v0.2.0", 1, &SHA)
            .lines()
            .filter(|l| !l.starts_with("plan_name="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(UpgradePlan::from_marker(&no_name).is_err());
        assert!(UpgradePlan::from_marker(&marker_text("v0.2.0", 1, &[0u8; 32])).is_err());
        assert!(UpgradePlan::from_marker(&marker_text("v0.2.0", 1, &SHA).replacen(
            &hex_encode(&SHA),
            "zz",
            1
        ))
        .is_err());
    }

    #[test]
    fn rpc_plan_parses_null_and_committed_shapes() {
        let none = serde_json::json!({
            "jsonrpc":"2.0","id":1,"result":{"applied":{"upgrade_plan":null}}
        });
        assert_eq!(UpgradePlan::from_rpc_value(&none).expect("null plan"), None);

        let some = serde_json::json!({
            "jsonrpc":"2.0","id":1,
            "result":{"applied":{"upgrade_plan":{
                "name":"v0.2.0","height":1200,"sha256":hex_encode(&SHA)
            }}}
        });
        assert_eq!(
            UpgradePlan::from_rpc_value(&some).expect("plan"),
            Some(plan_with(1200))
        );

        let err = serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"message":"nope"}});
        assert!(UpgradePlan::from_rpc_value(&err).is_err());
    }

    #[test]
    fn staged_binary_verification_accepts_exact_bytes_only() {
        let dir = temp_dir("verify");
        let path = dir.join("stellereum.new");
        write_exec(&path, b"verified binary");
        let expected = Sha256::digest(b"verified binary");
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&expected);
        let verified = verify_staged(&path, &sha).expect("digest matches");
        assert_eq!(verified.bytes, b"verified binary");
        assert_eq!(verified.sha256, sha);

        let wrong = [0x11u8; 32];
        let err = verify_staged(&path, &wrong).expect_err("digest mismatch must refuse");
        assert!(err.contains("sha256 mismatch"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn staged_symlink_and_world_writable_are_refused() {
        let dir = temp_dir("refuse");
        let real = dir.join("real");
        write_exec(&real, b"payload");
        let expected = {
            let d = Sha256::digest(b"payload");
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            out
        };
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = verify_staged(&link, &expected).expect_err("symlink must refuse");
        assert!(err.contains("SYMLINK"), "{err}");

        let writable = dir.join("writable");
        write_exec(&writable, b"payload");
        let mut perms = fs::metadata(&writable).expect("stat").permissions();
        perms.set_mode(0o757);
        fs::set_permissions(&writable, perms).expect("chmod");
        let err = verify_staged(&writable, &expected).expect_err("world-writable must refuse");
        assert!(err.contains("WORLD-WRITABLE"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_install_replaces_live_binary_and_dry_run_changes_nothing() {
        let dir = temp_dir("install");
        let staged = dir.join("staged");
        write_exec(&staged, b"new binary");
        let expected = {
            let d = Sha256::digest(b"new binary");
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            out
        };
        let verified = verify_staged(&staged, &expected).expect("verify");
        let live = dir.join("live");
        write_exec(&live, b"old binary");

        atomic_install(&live, &verified, true).expect("dry run");
        assert_eq!(fs::read(&live).expect("read"), b"old binary");

        atomic_install(&live, &verified, false).expect("install");
        assert_eq!(fs::read(&live).expect("read"), b"new binary");
        let mode = fs::metadata(&live).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let leftovers = fs::read_dir(&dir)
            .expect("dir")
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains(".upgrade-")
            })
            .count();
        assert_eq!(leftovers, 0, "no temp file may survive a successful rename");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn live_symlink_is_refused() {
        let dir = temp_dir("live-link");
        let target = dir.join("target");
        write_exec(&target, b"new");
        let verified = VerifiedBinary {
            sha256: SHA,
            bytes: b"new".to_vec(),
        };
        let link = dir.join("live");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = atomic_install(&link, &verified, false).expect_err("symlink live must refuse");
        assert!(err.contains("SYMLINK"), "{err}");
        assert_eq!(fs::read(&target).expect("target untouched"), b"new");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn progress_is_append_only_and_creates_parent() {
        let dir = temp_dir("progress").join("nested");
        let progress = Progress::new(dir.join("progress.log"));
        progress.record("verify", "sha256=ok").expect("record");
        progress.record("install", "renamed").expect("record");
        let text = fs::read_to_string(progress.path()).expect("read");
        assert!(text.contains("step=verify"));
        assert!(text.contains("step=install"));
        assert_eq!(text.lines().count(), 2);
        fs::remove_dir_all(dir.parent().expect("parent")).ok();
    }
}
