//! `stellereum-upgrader` operator CLI. See `src/lib.rs` for the safety rules.
//!
//! Dry-run is the default. A real swap requires `--apply`, a verified staged
//! binary, `--live`, and a `--restart-cmd`. Running as root refuses `--apply`
//! unless `--allow-root` is explicit.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use stellereum_upgrader::{
    atomic_install, backup_binary, backup_path_for, check_live_path, format_sha256_hex, is_root,
    resolve_staged_binary, rollback_binary_with_progress, run_restart_command,
    spawn_child_and_wait, systemd_unit_example, verify_post_upgrade_health, verify_staged,
    wait_for_marker, HealthCheckConfig, Progress, UpgradePlan, MARKER_HEADER, UPGRADE_EXIT_CODE,
    UPGRADE_VERSION_ENV, WAIT_SUPERMAJORITY_ENV,
};

const DEFAULT_MARKER: &str = "./data/upgrade-halt.marker";
const DEFAULT_PROGRESS: &str = "./data/upgrade-supervisor.progress";
const DEFAULT_WAIT_SECS: u64 = 3600;
const DEFAULT_POLL_MS: u64 = 500;
const DEFAULT_HEALTH_WAIT_SECS: u64 = 0;

#[derive(Clone, Debug)]
struct Args {
    marker: PathBuf,
    rpc: Option<String>,
    staged: Option<PathBuf>,
    staged_dir: Option<PathBuf>,
    live: Option<PathBuf>,
    restart_cmd: Option<String>,
    progress: PathBuf,
    wait_timeout: Duration,
    poll: Duration,
    health_url: Option<String>,
    health_wait_secs: u64,
    rollback_on_fail: bool,
    require_height_advance: bool,
    apply: bool,
    allow_root: bool,
    no_wait: bool,
    supervise: bool,
    set_wait_supermajority: bool,
    print_systemd: bool,
    child_args: Vec<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            marker: PathBuf::from(DEFAULT_MARKER),
            rpc: None,
            staged: None,
            staged_dir: None,
            live: None,
            restart_cmd: None,
            progress: PathBuf::from(DEFAULT_PROGRESS),
            wait_timeout: Duration::from_secs(DEFAULT_WAIT_SECS),
            poll: Duration::from_millis(DEFAULT_POLL_MS),
            health_url: None,
            health_wait_secs: DEFAULT_HEALTH_WAIT_SECS,
            rollback_on_fail: false,
            require_height_advance: false,
            apply: false,
            allow_root: false,
            no_wait: false,
            supervise: false,
            set_wait_supermajority: false,
            print_systemd: false,
            child_args: Vec::new(),
        }
    }
}

fn usage() -> String {
    format!(
        "stellereum-upgrader — Cosmovisor-like supervisor for a coordinated Stellereum upgrade\n\
\n\
USAGE:\n\
  stellereum-upgrader (--staged PATH | --staged-dir DIR) [--live PATH --restart-cmd CMD --apply] [OPTIONS]\n\
  stellereum-upgrader --supervise --live PATH (--staged PATH | --staged-dir DIR) [--apply] [OPTIONS] [-- NODE_ARGS...]\n\
\n\
PLAN SOURCE (one is required in practice):\n\
  --marker PATH          Halt marker written by the halted node\n\
                         (default: {DEFAULT_MARKER})\n\
  --rpc URL              Read the committed plan via stell_governanceParams\n\
                         (result.applied.upgrade_plan). If both are present\n\
                         their (name,height,sha256) must agree.\n\
\n\
BINARY:\n\
  --staged PATH          Staged target binary; its SHA-256 must match the plan.\n\
                         Refused if symlinked or world-writable.\n\
  --staged-dir DIR       Resolve staged binary as <DIR>/<plan_name>/stellereum.\n\
  --live PATH            Live binary to atomically replace (rename).\n\
  --restart-cmd CMD      Command run after the rename, via `sh -c`\n\
                         (e.g. 'systemctl --user restart stellereum').\n\
\n\
SUPERVISE MODE:\n\
  --supervise            Spawn --live with trailing `-- NODE_ARGS...`, catch exit\n\
                         code {UPGRADE_EXIT_CODE}, verify marker + staged binary, and\n\
                         with --apply atomically swap --live and respawn.\n\
  --set-wait-supermajority\n\
                         On --supervise respawn after upgrade, set\n\
                         {WAIT_SUPERMAJORITY_ENV}=<plan.height> and\n\
                         {UPGRADE_VERSION_ENV}=<plan.name>.\n\
  --print-systemd        Print reference systemd unit examples and exit.\n\
\n\
SAFETY:\n\
  --apply                Perform the rename/restart. Without it: DRY RUN.\n\
  --allow-root           Permit --apply while euid=0 (default: refuse).\n\
  --no-wait              Do not block for the halt marker (dry-run/inspection).\n\
  --wait-timeout SECS    Bound for waiting on plan/marker (default {DEFAULT_WAIT_SECS}s).\n\
  --poll-ms MS           Poll interval (default {DEFAULT_POLL_MS}ms).\n\
  --progress PATH        Append-only progress journal\n\
                         (default: {DEFAULT_PROGRESS}).\n\
\n\
HEALTH & AUTO-ROLLBACK:\n\
  --health-url URL       Post-upgrade health endpoint (JSON-RPC stell_blockNumber\n\
                         or GET .../health when URL path ends with /health).\n\
  --health-wait-secs N   Seconds to wait for post-upgrade health (default {DEFAULT_HEALTH_WAIT_SECS} = disabled).\n\
  --rollback-on-fail     On restart/health failure, restore <live>.prev -> <live>\n\
                         and re-run --restart-cmd.\n\
  --require-height-advance\n\
                         Require two probes showing height advance (or two /health 2xx).\n\
  -h, --help             Show this help.\n"
    )
}

fn non_empty_value(flag: &str, raw: String) -> Result<String, String> {
    if raw.trim().is_empty() {
        return Err(format!("{flag} cannot be empty"));
    }
    Ok(raw)
}

fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Option<Args>, String> {
    let mut parsed = Args::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            parsed.child_args.extend(iter);
            break;
        }
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg, None),
        };
        let mut value = |flag: &str| -> Result<String, String> {
            let raw = inline
                .clone()
                .or_else(|| iter.next())
                .ok_or_else(|| format!("{flag} needs a value"))?;
            non_empty_value(flag, raw)
        };
        match key.as_str() {
            "-h" | "--help" => return Ok(None),
            "--marker" => parsed.marker = PathBuf::from(value("--marker")?),
            "--rpc" => parsed.rpc = Some(value("--rpc")?),
            "--staged" => parsed.staged = Some(PathBuf::from(value("--staged")?)),
            "--staged-dir" => parsed.staged_dir = Some(PathBuf::from(value("--staged-dir")?)),
            "--live" => parsed.live = Some(PathBuf::from(value("--live")?)),
            "--restart-cmd" => parsed.restart_cmd = Some(value("--restart-cmd")?),
            "--progress" => parsed.progress = PathBuf::from(value("--progress")?),
            "--wait-timeout" => {
                let raw = value("--wait-timeout")?;
                let secs = raw
                    .parse::<u64>()
                    .map_err(|e| format!("--wait-timeout must be seconds: {e}"))?;
                if secs > 86_400 {
                    return Err("--wait-timeout is capped at one day".to_string());
                }
                parsed.wait_timeout = Duration::from_secs(secs);
            }
            "--poll-ms" => {
                let raw = value("--poll-ms")?;
                let ms = raw
                    .parse::<u64>()
                    .map_err(|e| format!("--poll-ms must be milliseconds: {e}"))?;
                if ms > 60_000 {
                    return Err("--poll-ms is capped at 60000".to_string());
                }
                parsed.poll = Duration::from_millis(ms);
            }
            "--health-url" => parsed.health_url = Some(value("--health-url")?),
            "--health-wait-secs" => {
                let raw = value("--health-wait-secs")?;
                let secs = raw
                    .parse::<u64>()
                    .map_err(|e| format!("--health-wait-secs must be seconds: {e}"))?;
                if secs > 86_400 {
                    return Err("--health-wait-secs is capped at one day".to_string());
                }
                parsed.health_wait_secs = secs;
            }
            "--rollback-on-fail" => parsed.rollback_on_fail = true,
            "--require-height-advance" => parsed.require_height_advance = true,
            "--apply" => parsed.apply = true,
            "--allow-root" => parsed.allow_root = true,
            "--no-wait" => parsed.no_wait = true,
            "--supervise" => parsed.supervise = true,
            "--set-wait-supermajority" => parsed.set_wait_supermajority = true,
            "--print-systemd" => parsed.print_systemd = true,
            other => return Err(format!("unknown argument {other:?} (try --help)")),
        }
    }
    if parsed.print_systemd {
        return Ok(Some(parsed));
    }
    if parsed.staged.is_some() && parsed.staged_dir.is_some() {
        return Err("cannot pass both --staged and --staged-dir".to_string());
    }
    if parsed.staged.is_none() && parsed.staged_dir.is_none() {
        return Err("--staged or --staged-dir is required".to_string());
    }
    if parsed.health_wait_secs > 0 && parsed.health_url.is_none() {
        return Err("--health-wait-secs > 0 requires --health-url".to_string());
    }
    if parsed.supervise {
        if parsed.live.is_none() {
            return Err("--supervise requires --live".to_string());
        }
        if parsed.restart_cmd.is_some() {
            return Err("--restart-cmd cannot be used with --supervise".to_string());
        }
    } else {
        if parsed.apply && parsed.live.is_none() {
            return Err("--apply requires --live".to_string());
        }
        if parsed.apply && parsed.restart_cmd.is_none() {
            return Err("--apply requires --restart-cmd".to_string());
        }
    }
    Ok(Some(parsed))
}

fn wait_for_rpc_plan(args: &Args, url: &str) -> Result<Option<UpgradePlan>, String> {
    let poll = args.poll.max(Duration::from_millis(10));
    let deadline = Instant::now() + args.wait_timeout;
    loop {
        match UpgradePlan::read_rpc(url) {
            Ok(Some(plan)) => return Ok(Some(plan)),
            Ok(None) => {
                // If the node just halted while we were polling, the marker is
                // now on disk; let the marker path proceed instead of waiting
                // forever for an RPC plan.
                if matches!(UpgradePlan::read_marker(&args.marker), Ok(Some(_))) {
                    return Ok(None);
                }
            }
            Err(e) => {
                // If the node already exited 42 and wrote the halt marker, its
                // RPC server is down; let the authoritative marker drive the
                // upgrade instead of aborting on connection refused.
                if matches!(UpgradePlan::read_marker(&args.marker), Ok(Some(_))) {
                    eprintln!(
                        "stellereum-upgrader: note: RPC {url} unreachable ({e}), but halt marker {} is present; using marker",
                        args.marker.display()
                    );
                    return Ok(None);
                }
                return Err(e);
            }
        }
        if args.no_wait {
            return Ok(None);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out after {:?} waiting for a committed plan at {url}",
                args.wait_timeout
            ));
        }
        std::thread::sleep(poll.min(deadline - now));
    }
}

fn same_plan(a: &UpgradePlan, b: &UpgradePlan) -> bool {
    a.name == b.name && a.height == b.height && a.sha256 == b.sha256
}

fn select_authoritative_plan(
    marker_plan: Option<UpgradePlan>,
    rpc_plan: Option<UpgradePlan>,
    args: &Args,
) -> Result<UpgradePlan, String> {
    let plan = match (marker_plan, rpc_plan) {
        (Some(marker), Some(rpc)) => {
            if !same_plan(&marker, &rpc) {
                return Err(format!(
                    "marker plan (name={}, height={}, sha256={}) disagrees with the committed \
                     RPC plan (name={}, height={}, sha256={}); refusing",
                    marker.name,
                    marker.height,
                    format_sha256_hex(&marker.sha256),
                    rpc.name,
                    rpc.height,
                    format_sha256_hex(&rpc.sha256),
                ));
            }
            marker
        }
        (Some(marker), None) => marker,
        (None, Some(rpc)) => rpc,
        (None, None) => {
            return Err(format!(
                "no upgrade plan: {} is absent and no RPC plan was read{}",
                args.marker.display(),
                if args.no_wait { " (--no-wait)" } else { "" }
            ))
        }
    };
    if plan.sha256 == [0u8; 32] {
        return Err("plan sha256 is all zero; refusing".to_string());
    }
    Ok(plan)
}

fn run_supervise(args: &Args, progress: &Progress) -> Result<(), String> {
    let live = args
        .live
        .as_ref()
        .ok_or_else(|| "--supervise requires --live".to_string())?;
    check_live_path(live)?;
    let mut extra_env: Vec<(&str, String)> = Vec::new();
    let mut generation: u64 = 0;

    loop {
        generation = generation.saturating_add(1);
        progress.record(
            "spawn",
            &format!("gen={generation} live={}", live.display()),
        )?;
        let status = spawn_child_and_wait(live, &args.child_args, &extra_env).map_err(|e| {
            let _ = progress.record("error", &format!("spawn {e}"));
            e
        })?;
        let code = status.code();
        if code != Some(UPGRADE_EXIT_CODE) {
            if status.success() {
                progress.record("child-exit", &format!("gen={generation} code=0"))?;
                return Ok(());
            }
            let msg = format!(
                "child {} exited with {status} (not upgrade halt code {UPGRADE_EXIT_CODE})",
                live.display()
            );
            let _ = progress.record("child-exit", &format!("gen={generation} status={status}"));
            return Err(msg);
        }

        progress.record(
            "halt-exit-42",
            &format!("gen={generation} marker={}", args.marker.display()),
        )?;
        let marker_plan = if args.no_wait {
            UpgradePlan::read_marker(&args.marker)?
        } else {
            Some(
                wait_for_marker(&args.marker, args.wait_timeout, args.poll).map_err(|e| {
                    let _ = progress.record("error", &format!("marker {e}"));
                    e
                })?,
            )
        };
        let rpc_plan = match args.rpc.as_deref() {
            Some(url) => wait_for_rpc_plan(args, url).map_err(|e| {
                let _ = progress.record("error", &format!("rpc-plan {e}"));
                e
            })?,
            None => None,
        };
        if let Some(plan) = &rpc_plan {
            progress.record(
                "plan-rpc",
                &format!(
                    "name={} height={} sha256={}",
                    plan.name,
                    plan.height,
                    format_sha256_hex(&plan.sha256)
                ),
            )?;
        }
        let plan = select_authoritative_plan(marker_plan, rpc_plan, args)?;
        progress.record(
            "halt-marker",
            &format!(
                "name={} height={} sha256={}",
                plan.name,
                plan.height,
                format_sha256_hex(&plan.sha256)
            ),
        )?;

        let staged_path = resolve_staged_binary(
            args.staged.as_deref(),
            args.staged_dir.as_deref(),
            &plan.name,
        )?;
        let verified = verify_staged(&staged_path, &plan.sha256).map_err(|e| {
            let _ = progress.record("error", &format!("verify {e}"));
            e
        })?;
        println!(
            "staged binary verified: {} bytes, sha256 {}",
            verified.bytes.len(),
            format_sha256_hex(&verified.sha256)
        );
        progress.record(
            "verify",
            &format!(
                "staged={} bytes={} sha256={}",
                staged_path.display(),
                verified.bytes.len(),
                format_sha256_hex(&verified.sha256)
            ),
        )?;

        if !args.apply {
            println!(
                "DRY RUN: child exited {UPGRADE_EXIT_CODE}; staged binary {} verified, but --apply \
                 was not set so {} was not replaced and child was not respawned.",
                staged_path.display(),
                live.display()
            );
            progress.record("dry-run", "verified after exit 42; nothing changed")?;
            return Ok(());
        }

        atomic_install(live, &verified, false).map_err(|e| {
            let _ = progress.record("error", &format!("install {e}"));
            e
        })?;
        println!("installed verified bytes at {}", live.display());
        progress.record(
            "install",
            &format!(
                "live={} sha256={}",
                live.display(),
                format_sha256_hex(&verified.sha256)
            ),
        )?;

        extra_env.clear();
        if args.set_wait_supermajority {
            extra_env.push((WAIT_SUPERMAJORITY_ENV, plan.height.to_string()));
            extra_env.push((UPGRADE_VERSION_ENV, plan.name.clone()));
        }
        progress.record("restart", &format!("respawn live={}", live.display()))?;
    }
}

fn run() -> Result<(), String> {
    let Some(args) = parse_args(std::env::args().skip(1))? else {
        print!("{}", usage());
        return Ok(());
    };
    if args.print_systemd {
        print!("{}", systemd_unit_example());
        return Ok(());
    }
    if args.apply && is_root() && !args.allow_root {
        return Err(
            "refusing --apply while running as root: the supervisor does not need root, and a \
             silent root-owned rename is exactly the accident this guard prevents. Run it as the \
             service user, or pass --allow-root after reviewing the paths."
                .to_string(),
        );
    }

    let progress = Progress::new(args.progress.clone());
    progress.record(
        "start",
        &format!(
            "apply={} supervise={} allow_root={} marker={} rpc={} staged={} staged_dir={} live={}",
            args.apply,
            args.supervise,
            args.allow_root,
            args.marker.display(),
            args.rpc.as_deref().unwrap_or("-"),
            args.staged
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
            args.staged_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
            args.live
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
    )?;

    if args.supervise {
        return run_supervise(&args, &progress);
    }

    // 1. Plan. RPC is a pre-halt source; the marker is the authoritative halt
    //    record. If BOTH exist they must agree, or we refuse rather than pick.
    let rpc_plan = match args.rpc.as_deref() {
        Some(url) => wait_for_rpc_plan(&args, url).map_err(|e| {
            let _ = progress.record("error", &format!("rpc-plan {e}"));
            e
        })?,
        None => None,
    };
    if let Some(plan) = &rpc_plan {
        progress.record(
            "plan-rpc",
            &format!(
                "name={} height={} sha256={}",
                plan.name,
                plan.height,
                format_sha256_hex(&plan.sha256)
            ),
        )?;
    }

    let marker_plan = if args.no_wait {
        UpgradePlan::read_marker(&args.marker)?
    } else {
        Some(
            wait_for_marker(&args.marker, args.wait_timeout, args.poll).map_err(|e| {
                let _ = progress.record("error", &format!("marker {e}"));
                e
            })?,
        )
    };
    if let Some(plan) = &marker_plan {
        progress.record(
            "halt-marker",
            &format!(
                "name={} height={} sha256={}",
                plan.name,
                plan.height,
                format_sha256_hex(&plan.sha256)
            ),
        )?;
    }

    let plan = select_authoritative_plan(marker_plan, rpc_plan, &args)?;

    println!("plan: {}", plan.name);
    println!("halt height: {}", plan.height);
    println!("plan sha256: {}", format_sha256_hex(&plan.sha256));
    println!("marker format: {MARKER_HEADER}");

    // 2. Verify the staged bytes BEFORE any filesystem mutation.
    let staged_path = resolve_staged_binary(
        args.staged.as_deref(),
        args.staged_dir.as_deref(),
        &plan.name,
    )?;
    let verified = verify_staged(&staged_path, &plan.sha256).map_err(|e| {
        let _ = progress.record("error", &format!("verify {e}"));
        e
    })?;
    println!(
        "staged binary verified: {} bytes, sha256 {}",
        verified.bytes.len(),
        format_sha256_hex(&verified.sha256)
    );
    progress.record(
        "verify",
        &format!(
            "staged={} bytes={} sha256={}",
            staged_path.display(),
            verified.bytes.len(),
            format_sha256_hex(&verified.sha256)
        ),
    )?;

    // 3. Dry-run (default) stops here after proving every refusal would pass.
    if !args.apply {
        println!(
            "DRY RUN: no binary was replaced and no service was restarted. Re-run with --apply \
             --live <path> --restart-cmd <cmd> to execute the plan."
        );
        progress.record("dry-run", "verified only; nothing changed")?;
        return Ok(());
    }

    let live = args
        .live
        .as_ref()
        .ok_or_else(|| "--apply requires --live".to_string())?;
    let restart = args
        .restart_cmd
        .as_deref()
        .ok_or_else(|| "--apply requires --restart-cmd".to_string())?;
    let backup = backup_path_for(live);

    if args.rollback_on_fail {
        if std::fs::symlink_metadata(live).is_ok() {
            backup_binary(live, &backup, false).map_err(|e| {
                let _ = progress.record("error", &format!("backup {e}"));
                e
            })?;
            progress.record(
                "backup",
                &format!("live={} backup={}", live.display(), backup.display()),
            )?;
        } else if !backup.exists() {
            let msg = format!(
                "--rollback-on-fail requires existing {} or backup {}",
                live.display(),
                backup.display()
            );
            let _ = progress.record("error", &format!("backup {msg}"));
            return Err(msg);
        }
    }

    atomic_install(live, &verified, false).map_err(|e| {
        let _ = progress.record("error", &format!("install {e}"));
        e
    })?;
    println!("installed verified bytes at {}", live.display());
    progress.record(
        "install",
        &format!(
            "live={} sha256={}",
            live.display(),
            format_sha256_hex(&verified.sha256)
        ),
    )?;

    if let Err(e) = run_restart_command(restart) {
        let _ = progress.record("error", &format!("restart {e}"));
        if args.rollback_on_fail {
            eprintln!(
                "stellereum-upgrader: restart failed ({e}); rolling back {} from {}",
                live.display(),
                backup.display()
            );
            let _ =
                rollback_binary_with_progress(live, &backup, Some(restart), false, Some(&progress));
        }
        return Err(e);
    }
    println!("restart command completed: {restart}");
    progress.record("restart", &format!("cmd={restart}"))?;

    if args.health_wait_secs > 0 {
        let health_url = args
            .health_url
            .clone()
            .ok_or_else(|| "--health-wait-secs > 0 requires --health-url".to_string())?;
        let cfg = HealthCheckConfig {
            url: health_url,
            timeout_secs: args.health_wait_secs,
            poll_interval_ms: args.poll.as_millis() as u64,
            require_height_advance: args.require_height_advance,
        };
        if let Err(health_err) = verify_post_upgrade_health(&cfg) {
            let _ = progress.record("error", &format!("health-check {health_err}"));
            if args.rollback_on_fail {
                eprintln!(
                    "stellereum-upgrader: health check failed ({health_err}); rolling back {} from {}",
                    live.display(),
                    backup.display()
                );
                rollback_binary_with_progress(
                    live,
                    &backup,
                    Some(restart),
                    false,
                    Some(&progress),
                )?;
                return Err(format!(
                    "post-upgrade health check failed ({health_err}); rolled back {} from {}",
                    live.display(),
                    backup.display()
                ));
            }
            return Err(health_err);
        }
        println!("post-upgrade health check passed: {}", cfg.url);
        progress.record("health-check", &format!("url={} status=ok", cfg.url))?;
    }

    progress.record("done", "upgrade supervisor completed")?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("stellereum-upgrader: ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svec(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parse_args_supports_watcher_and_supervise_modes() {
        let watcher = parse_args(svec(&["--staged", "/tmp/new", "--no-wait"]))
            .expect("ok")
            .expect("some");
        assert!(!watcher.apply);
        assert!(!watcher.supervise);
        assert!(watcher.no_wait);

        let sup = parse_args(svec(&[
            "--supervise",
            "--live",
            "/tmp/live",
            "--staged-dir",
            "/tmp/upgrades",
            "--set-wait-supermajority",
            "--apply",
            "--",
            "run",
            "--config",
            "node.yaml",
        ]))
        .expect("ok")
        .expect("some");
        assert!(sup.supervise);
        assert!(sup.apply);
        assert!(sup.set_wait_supermajority);
        assert_eq!(sup.child_args, svec(&["run", "--config", "node.yaml"]));

        let sysd = parse_args(svec(&["--print-systemd"]))
            .expect("ok")
            .expect("some");
        assert!(sysd.print_systemd);

        let health = parse_args(svec(&[
            "--staged",
            "/tmp/new",
            "--live",
            "/tmp/live",
            "--restart-cmd",
            "true",
            "--health-url",
            "http://127.0.0.1:8545",
            "--health-wait-secs",
            "15",
            "--rollback-on-fail",
            "--require-height-advance",
            "--apply",
        ]))
        .expect("ok")
        .expect("some");
        assert_eq!(health.health_url.as_deref(), Some("http://127.0.0.1:8545"));
        assert_eq!(health.health_wait_secs, 15);
        assert!(health.rollback_on_fail);
        assert!(health.require_height_advance);
    }

    #[test]
    fn parse_args_rejects_invalid_combinations() {
        assert!(parse_args(svec(&["--staged", "/a", "--staged-dir", "/b"])).is_err());
        assert!(parse_args(svec(&["--supervise", "--staged", "/a"])).is_err());
        assert!(parse_args(svec(&[
            "--supervise",
            "--live",
            "/l",
            "--staged",
            "/a",
            "--restart-cmd",
            "true"
        ]))
        .is_err());
        assert!(parse_args(svec(&["--staged", "/a", "--apply"])).is_err());
        assert!(parse_args(svec(&["--staged="])).is_err());
        assert!(parse_args(svec(&["--staged", "/a", "--live="])).is_err());
        assert!(parse_args(svec(&["--staged", "/a", "--health-wait-secs", "5"])).is_err());
    }

    #[test]
    fn select_authoritative_plan_enforces_rpc_marker_agreement() {
        let args = Args::default();
        let p1 = UpgradePlan {
            name: "v0.2.0".to_string(),
            height: 1200,
            sha256: [0xabu8; 32],
        };
        let p2 = UpgradePlan {
            name: "v0.2.1".to_string(),
            height: 1200,
            sha256: [0xabu8; 32],
        };
        assert_eq!(
            select_authoritative_plan(Some(p1.clone()), Some(p1.clone()), &args).expect("agree"),
            p1
        );
        let err = select_authoritative_plan(Some(p1), Some(p2), &args)
            .expect_err("disagreeing marker and rpc plan must refuse");
        assert!(err.contains("disagrees"), "{err}");
    }
}
