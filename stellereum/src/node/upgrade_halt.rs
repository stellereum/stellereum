//! Durable upgrade-halt marker + startup safety guard.
//!
//! `docs/UPGRADE_AND_RECOVERY.md` §1.2.3/§1.2.4 names two holes in the
//! software-upgrade path:
//!
//! 1. `std::process::exit(42)` skipped the SIGTERM drain (`exit(0)` path in
//!    `node/bootstrap.rs`), so jobs still in the `AsyncPersistence` queue were
//!    lost on the halt. The halt lane now awaits
//!    [`drain_for_halt`] before it writes the marker and exits.
//! 2. The finalize-lane trigger is an EVENT. A node that was offline at the
//!    plan height, or that restarted past it, never fired and kept running the
//!    OLD rules (a silent straggler). Before exiting, the halt lane now writes
//!    a durable marker ([`UpgradeHaltMarker`]) next to the store; on startup
//!    [`guard_upgrade_halt`] reads it and REFUSES to start consensus unless the
//!    running binary reports the plan's target version.
//!
//! This module is pure with respect to consensus state: it reads/writes one
//! small text file in the data directory and never touches the wire format,
//! the commitment digest or any applied state. It is included by path from
//! `node/bootstrap.rs` and by `tests/upgrade_halt_tests.rs`, so it must stay
//! self-contained (only `std`, `sha2`, `hex` and the already-public
//! `stellereum::storage` drain helper).
//!
//! ## Marker format (versioned, line oriented, fail-closed on parse)
//!
//! ```text
//! stell-upgrade-halt v1
//! height=1200
//! halted_at_height=1200
//! plan_name=v0.2.0
//! plan_sha256=<64 lowercase hex chars>
//! target_version=v0.2.0
//! running_version=0.1.0
//! halted_unix=1763500000
//! ```
//!
//! `height` is the PLAN's halt height (the predicate the startup guard
//! compares against the finalized head); `halted_at_height` is the finalized
//! height at which this node actually halted (equal to `height` normally,
//! greater when the node missed the event and halted late).

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use stellereum::storage::{wait_for_persist_drain_with, ShutdownDrainConfig, ShutdownDrainOutcome};

/// Exact first line of every marker file. A future format MUST bump the
/// version here, so an old binary refuses a newer marker loudly instead of
/// misreading it.
pub const MARKER_HEADER: &str = "stell-upgrade-halt v1";

/// Default marker location, relative to the node's working directory (the
/// same `./data` the store lives in, `node/policy.rs::store_path_for_shard`).
pub const MARKER_FILE_NAME: &str = "upgrade-halt.marker";

/// Override the marker path (tests, and nodes that run with a non-default
/// working directory).
pub const MARKER_PATH_ENV: &str = "STELL_UPGRADE_HALT_MARKER";

/// The version a running binary DECLARES it implements.
///
/// Unset, the binary reports its compiled crate version
/// (`CARGO_PKG_VERSION`). Set it in the new binary's unit file to the upgrade
/// plan's `name` when the binary was rebuilt (so its SHA-256 no longer matches
/// the plan digest). It is a declaration, never a downgrade switch: an
/// unsatisfied marker is refused, so leaving it unset can only make the guard
/// STRICTER.
pub const RUNNING_VERSION_ENV: &str = "STELL_UPGRADE_VERSION";

/// The data directory the node runs against, as seen from the process cwd.
const DATA_DIR: &str = "./data";

/// Path of the halt marker: `$STELL_UPGRADE_HALT_MARKER`, else
/// `./data/upgrade-halt.marker`.
pub fn marker_path() -> PathBuf {
    match std::env::var(MARKER_PATH_ENV) {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
        _ => Path::new(DATA_DIR).join(MARKER_FILE_NAME),
    }
}

/// Durable record of "this data directory halted for an upgrade".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeHaltMarker {
    /// The plan's halt height — the predicate the startup guard applies.
    pub height: u64,
    /// The finalized height at which this node actually halted.
    pub halted_at_height: u64,
    /// The plan's human name (`UpgradePlan::name`).
    pub plan_name: String,
    /// The plan's binary digest (`UpgradePlan::sha256`).
    pub plan_sha256: [u8; 32],
    /// The version the upgraded binary must report (the plan name).
    pub target_version: String,
    /// The version the halting binary reported.
    pub running_version: String,
    /// Wall-clock halt time (seconds since the Unix epoch).
    pub halted_unix: u64,
}

impl UpgradeHaltMarker {
    /// Render the exact on-disk text (see the module docs for the format).
    pub fn render(&self) -> String {
        let height = self.height;
        let halted_at_height = self.halted_at_height;
        let plan_name = &self.plan_name;
        let plan_sha256 = hex::encode(self.plan_sha256);
        let target_version = &self.target_version;
        let running_version = &self.running_version;
        let halted_unix = self.halted_unix;
        format!(
            "{MARKER_HEADER}\n\
             height={height}\n\
             halted_at_height={halted_at_height}\n\
             plan_name={plan_name}\n\
             plan_sha256={plan_sha256}\n\
             target_version={target_version}\n\
             running_version={running_version}\n\
             halted_unix={halted_unix}\n"
        )
    }

    /// Parse a marker file. Strict on the header and the required keys,
    /// tolerant of unknown `key=value` lines (forward compatible inside v1).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        match lines.next() {
            Some(first) if first.trim() == MARKER_HEADER => {}
            Some(other) => return Err(format!("bad marker header: {other:?}")),
            None => return Err("empty marker file".to_string()),
        }
        let mut height: Option<u64> = None;
        let mut halted_at_height: Option<u64> = None;
        let mut plan_name: Option<String> = None;
        let mut plan_sha256: Option<[u8; 32]> = None;
        let mut target_version: Option<String> = None;
        let mut running_version: Option<String> = None;
        let mut halted_unix: Option<u64> = None;
        for raw in lines {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("malformed marker line: {line:?}"));
            };
            match key {
                "height" => {
                    height = Some(
                        value
                            .parse::<u64>()
                            .map_err(|e| format!("bad height: {e}"))?,
                    )
                }
                "halted_at_height" => {
                    halted_at_height = Some(
                        value
                            .parse::<u64>()
                            .map_err(|e| format!("bad halted_at_height: {e}"))?,
                    )
                }
                "plan_name" => plan_name = Some(required_text(key, value)?),
                "plan_sha256" => {
                    let bytes =
                        hex::decode(value).map_err(|e| format!("bad plan_sha256 hex: {e}"))?;
                    let arr: [u8; 32] = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| "plan_sha256 must be exactly 32 bytes".to_string())?;
                    plan_sha256 = Some(arr);
                }
                "target_version" => target_version = Some(required_text(key, value)?),
                "running_version" => running_version = Some(value.trim().to_string()),
                "halted_unix" => {
                    halted_unix = Some(
                        value
                            .parse::<u64>()
                            .map_err(|e| format!("bad halted_unix: {e}"))?,
                    )
                }
                // Forward compatibility inside v1: a later writer may add
                // fields, and refusing them would brick a rollback that only
                // needs the fields above.
                _ => {}
            }
        }
        Ok(Self {
            height: height.ok_or_else(|| "missing marker field 'height'".to_string())?,
            halted_at_height: halted_at_height
                .ok_or_else(|| "missing marker field 'halted_at_height'".to_string())?,
            plan_name: plan_name.ok_or_else(|| "missing marker field 'plan_name'".to_string())?,
            plan_sha256: plan_sha256
                .ok_or_else(|| "missing marker field 'plan_sha256'".to_string())?,
            target_version: target_version
                .ok_or_else(|| "missing marker field 'target_version'".to_string())?,
            running_version: running_version
                .ok_or_else(|| "missing marker field 'running_version'".to_string())?,
            halted_unix: halted_unix
                .ok_or_else(|| "missing marker field 'halted_unix'".to_string())?,
        })
    }
}

fn required_text(key: &str, value: &str) -> Result<String, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(format!("empty marker field {key:?}"));
    }
    if v.contains('\n') || v.contains('\r') {
        return Err(format!("marker field {key:?} carries a newline"));
    }
    Ok(v.to_string())
}

/// Atomically write the marker: temp file in the same directory, `fsync`,
/// rename, then `fsync` the directory. A torn marker is worse than none, so a
/// failure here is reported to the caller (the halt still proceeds).
pub fn write_marker(path: &Path, marker: &UpgradeHaltMarker) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(marker.render().as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    sync_parent(path);
    Ok(())
}

/// Read the marker. `Ok(None)` means "not halted for an upgrade"; a malformed
/// file is an `InvalidData` error (fail closed at the call site).
pub fn read_marker(path: &Path) -> std::io::Result<Option<UpgradeHaltMarker>> {
    match std::fs::read_to_string(path) {
        Ok(text) => UpgradeHaltMarker::parse(&text).map(Some).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove the marker. Returns `true` when a file was removed.
pub fn clear_marker(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            sync_parent(path);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn sync_parent(path: &Path) {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// The version this binary reports. `STELL_UPGRADE_VERSION` (trimmed,
/// non-empty) wins; otherwise the compiled crate version.
pub fn running_version() -> String {
    match std::env::var(RUNNING_VERSION_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// SHA-256 of the running executable (`/proc/self/exe`), the value the plan's
/// `sha256` names. `None` where the kernel does not expose the image (then the
/// version string is the only identity, which is the stricter direction).
pub fn running_exe_sha256() -> Option<[u8; 32]> {
    let bytes = std::fs::read("/proc/self/exe").ok()?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Some(out)
}

/// Compare two advertised versions: trim, drop one leading `v`/`V`, lowercase.
pub fn normalize_version(v: &str) -> String {
    let t = v.trim();
    let t = t
        .strip_prefix('v')
        .or_else(|| t.strip_prefix('V'))
        .unwrap_or(t);
    t.trim().to_ascii_lowercase()
}

/// TRUE when the running binary proves it is the binary the plan named: the
/// executable digest matches the plan digest, or the declared version equals
/// the marker's target version.
pub fn marker_satisfied_by(
    marker: &UpgradeHaltMarker,
    running_version: &str,
    running_sha: Option<[u8; 32]>,
) -> bool {
    if let Some(sha) = running_sha {
        if sha == marker.plan_sha256 {
            return true;
        }
    }
    let mine = normalize_version(running_version);
    !mine.is_empty() && mine == normalize_version(&marker.target_version)
}

/// What the startup guard decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HaltDecision {
    /// No marker: this data directory was not halted for an upgrade.
    Proceed,
    /// The marker's halt height is not reached yet (finalized < height).
    Pending { marker: UpgradeHaltMarker },
    /// A stale marker was satisfied by this binary and removed.
    Cleared { marker: UpgradeHaltMarker },
    /// REFUSE to start consensus. `message` is operator-facing and names the
    /// marker file and the expected version.
    Refuse { message: String },
}

/// The startup guard: refuse consensus on a stale, unsatisfied marker.
///
/// `finalized` and `running_sha` are read LAZILY (only when a marker exists)
/// so a node without a marker pays nothing -- in particular it does not hash
/// its own executable -- and keeps the old startup path byte-for-byte.
pub fn guard_upgrade_halt(
    path: &Path,
    finalized: impl FnOnce() -> Result<Option<u64>, String>,
    running_version: &str,
    running_sha: impl FnOnce() -> Option<[u8; 32]>,
) -> HaltDecision {
    match read_marker(path) {
        Ok(None) => HaltDecision::Proceed,
        Ok(Some(marker)) => {
            let finalized_height = match finalized() {
                Ok(h) => h.unwrap_or(0),
                Err(e) => {
                    return HaltDecision::Refuse {
                        message: unreadable_head_message(path, &marker, &e),
                    }
                }
            };
            decide(
                path,
                marker,
                finalized_height,
                running_version,
                running_sha(),
                true,
            )
        }
        Err(e) => HaltDecision::Refuse {
            message: unreadable_marker_message(path, &e),
        },
    }
}

/// Same comparison as [`guard_upgrade_halt`], but READ-ONLY: a stale marker
/// that the running binary satisfies is reported as [`HaltDecision::Cleared`]
/// and is NOT removed. The `upgrade-status` CLI uses it to print exactly the
/// message the node's startup guard would produce, without mutating the data
/// directory.
pub fn preview_halt_decision(
    path: &Path,
    finalized_height: u64,
    running_version: &str,
    running_sha: Option<[u8; 32]>,
) -> HaltDecision {
    match read_marker(path) {
        Ok(Some(marker)) => decide(
            path,
            marker,
            finalized_height,
            running_version,
            running_sha,
            false,
        ),
        Ok(None) => HaltDecision::Proceed,
        Err(e) => HaltDecision::Refuse {
            message: unreadable_marker_message(path, &e),
        },
    }
}

/// Pure decision core of [`guard_upgrade_halt`] with the finalized head
/// already resolved and the marker already read. `clear` decides whether a
/// satisfied marker is removed (startup) or only reported (status preview).
fn decide(
    path: &Path,
    marker: UpgradeHaltMarker,
    finalized_height: u64,
    running_version: &str,
    running_sha: Option<[u8; 32]>,
    clear: bool,
) -> HaltDecision {
    if marker.height > finalized_height {
        return HaltDecision::Pending { marker };
    }
    if marker_satisfied_by(&marker, running_version, running_sha) {
        if !clear {
            return HaltDecision::Cleared { marker };
        }
        return match clear_marker(path) {
            Ok(_) => HaltDecision::Cleared { marker },
            Err(e) => HaltDecision::Refuse {
                message: clear_failed_message(path, &marker, &e),
            },
        };
    }
    HaltDecision::Refuse {
        message: refusal_message(
            path,
            &marker,
            finalized_height,
            running_version,
            running_sha,
        ),
    }
}

fn hex_or_unknown(sha: Option<[u8; 32]>) -> String {
    sha.map(hex::encode)
        .unwrap_or_else(|| "unknown (no /proc/self/exe)".to_string())
}

fn refusal_message(
    path: &Path,
    marker: &UpgradeHaltMarker,
    finalized_height: u64,
    running_version: &str,
    running_sha: Option<[u8; 32]>,
) -> String {
    let file = path.display();
    let plan_name = &marker.plan_name;
    let plan_sha = hex::encode(marker.plan_sha256);
    let target = &marker.target_version;
    let halted_at = marker.halted_at_height;
    let height = marker.height;
    let running_sha = hex_or_unknown(running_sha);
    format!(
        "[upgrade] REFUSING TO START CONSENSUS: this data directory is halted for a software \
         upgrade at height {height} (finalized head {finalized_height}; this node halted at \
         {halted_at}) and the running binary does not implement the plan's target version.\n\
         \x20 marker file:             {file}\n\
         \x20 expected target version: '{target}' (plan '{plan_name}', sha256 {plan_sha})\n\
         \x20 running binary version:  '{running_version}' (exe sha256 {running_sha})\n\
         Action: install the binary the plan names (its sha256 must match the plan digest) and \
         restart; the marker is cleared automatically once the running binary proves it is the \
         upgraded one. If this binary was rebuilt and implements the plan, declare it with \
         {RUNNING_VERSION_ENV}={target} in the unit's environment and restart. Only delete {file} \
         by hand after verifying out of band that the pre-upgrade rules are no longer live."
    )
}

fn unreadable_marker_message(path: &Path, err: &std::io::Error) -> String {
    let file = path.display();
    format!(
        "[upgrade] REFUSING TO START CONSENSUS: the upgrade-halt marker {file} exists but cannot \
         be read ({err}). A node that cannot prove it is not halted must not vote. Restore the \
         marker from a backup, or delete it after verifying out of band that no software upgrade \
         is pending, then restart."
    )
}

fn unreadable_head_message(path: &Path, marker: &UpgradeHaltMarker, err: &str) -> String {
    let file = path.display();
    let height = marker.height;
    format!(
        "[upgrade] REFUSING TO START CONSENSUS: the upgrade-halt marker {file} names halt height \
         {height}, but the local finalized head could not be read ({err}), so the node cannot \
         prove it is below the halt height. Restore a verified backup of the store, or delete \
         {file} after verifying out of band that no software upgrade is pending, then restart."
    )
}

fn clear_failed_message(path: &Path, marker: &UpgradeHaltMarker, err: &std::io::Error) -> String {
    let file = path.display();
    let target = &marker.target_version;
    format!(
        "[upgrade] REFUSING TO START CONSENSUS: the running binary satisfies the upgrade plan \
         (target version '{target}') but the stale halt marker {file} could not be removed \
         ({err}). Fix the permissions on the data directory (or delete the marker) and restart; \
         the guard cannot tell a cleared marker from one it merely meant to clear."
    )
}

/// Drain the persistence queue before the upgrade exit, bounded by `cfg`.
///
/// `exit(42)` used to skip the SIGTERM drain, so in-flight bodies/snapshots
/// were lost on the halt. This is the halt lane's ONLY durability wait; the
/// production budget is [`ShutdownDrainConfig::default`] (240 s cap + 10 s
/// settle), so a dead disk can never hang the halt forever.
pub async fn drain_for_halt(
    pending: impl Fn() -> u64,
    cfg: ShutdownDrainConfig,
) -> ShutdownDrainOutcome {
    wait_for_persist_drain_with(pending, cfg).await
}
