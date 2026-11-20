//! `stellereum-upgrader` operator CLI. See `src/lib.rs` for the safety rules.
//!
//! Dry-run is the default. A real swap requires `--apply`, a verified staged
//! binary, `--live`, and a `--restart-cmd`. Running as root refuses `--apply`
//! unless `--allow-root` is explicit.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use stellereum_upgrader::{
    atomic_install, is_root, run_restart_command, verify_staged, wait_for_marker, Progress,
    UpgradePlan, MARKER_HEADER,
};

const DEFAULT_MARKER: &str = "./data/upgrade-halt.marker";
const DEFAULT_PROGRESS: &str = "./data/upgrade-supervisor.progress";
const DEFAULT_WAIT_SECS: u64 = 3600;
const DEFAULT_POLL_MS: u64 = 500;

#[derive(Clone, Debug)]
struct Args {
    marker: PathBuf,
    rpc: Option<String>,
    staged: PathBuf,
    live: Option<PathBuf>,
    restart_cmd: Option<String>,
    progress: PathBuf,
    wait_timeout: Duration,
    poll: Duration,
    apply: bool,
    allow_root: bool,
    no_wait: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            marker: PathBuf::from(DEFAULT_MARKER),
            rpc: None,
            staged: PathBuf::new(),
            live: None,
            restart_cmd: None,
            progress: PathBuf::from(DEFAULT_PROGRESS),
            wait_timeout: Duration::from_secs(DEFAULT_WAIT_SECS),
            poll: Duration::from_millis(DEFAULT_POLL_MS),
            apply: false,
            allow_root: false,
            no_wait: false,
        }
    }
}

fn usage() -> String {
    format!(
        "stellereum-upgrader — Cosmovisor-like supervisor for a coordinated Stellereum upgrade\n\
\n\
USAGE:\n\
  stellereum-upgrader --staged PATH [--live PATH --restart-cmd CMD --apply] [OPTIONS]\n\
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
  --live PATH            Live binary to atomically replace (rename).\n\
  --restart-cmd CMD      Command run after the rename, via `sh -c`\n\
                         (e.g. 'systemctl --user restart stellereum').\n\
\n\
SAFETY:\n\
  --apply                Perform the rename/restart. Without it: DRY RUN.\n\
  --allow-root           Permit --apply while euid=0 (default: refuse).\n\
  --no-wait              Do not block for the halt marker (dry-run/inspection).\n\
  --wait-timeout SECS    Bound for waiting on plan/marker (default {DEFAULT_WAIT_SECS}s).\n\
  --poll-ms MS           Poll interval (default {DEFAULT_POLL_MS}ms).\n\
  --progress PATH        Append-only progress journal\n\
                         (default: {DEFAULT_PROGRESS}).\n\
  -h, --help             Show this help.\n"
    )
}

fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Option<Args>, String> {
    let mut parsed = Args::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg, None),
        };
        let mut value = |flag: &str| -> Result<String, String> {
            inline
                .clone()
                .or_else(|| iter.next())
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match key.as_str() {
            "-h" | "--help" => return Ok(None),
            "--marker" => parsed.marker = PathBuf::from(value("--marker")?),
            "--rpc" => parsed.rpc = Some(value("--rpc")?),
            "--staged" => parsed.staged = PathBuf::from(value("--staged")?),
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
            "--apply" => parsed.apply = true,
            "--allow-root" => parsed.allow_root = true,
            "--no-wait" => parsed.no_wait = true,
            other => return Err(format!("unknown argument {other:?} (try --help)")),
        }
    }
    if parsed.staged.as_os_str().is_empty() {
        return Err("--staged is required".to_string());
    }
    if parsed.apply && parsed.live.is_none() {
        return Err("--apply requires --live".to_string());
    }
    if parsed.apply && parsed.restart_cmd.is_none() {
        return Err("--apply requires --restart-cmd".to_string());
    }
    Ok(Some(parsed))
}

fn wait_for_rpc_plan(args: &Args, url: &str) -> Result<Option<UpgradePlan>, String> {
    let deadline = Instant::now() + args.wait_timeout;
    loop {
        match UpgradePlan::read_rpc(url) {
            Ok(Some(plan)) => return Ok(Some(plan)),
            Ok(None) => {}
            Err(e) => return Err(e),
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
        std::thread::sleep(args.poll.min(deadline - now));
    }
}

fn same_plan(a: &UpgradePlan, b: &UpgradePlan) -> bool {
    a.name == b.name && a.height == b.height && a.sha256 == b.sha256
}

fn run() -> Result<(), String> {
    let Some(args) = parse_args(std::env::args().skip(1))? else {
        print!("{}", usage());
        return Ok(());
    };
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
            "apply={} allow_root={} marker={} rpc={} staged={} live={}",
            args.apply,
            args.allow_root,
            args.marker.display(),
            args.rpc.as_deref().unwrap_or("-"),
            args.staged.display(),
            args.live
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
    )?;

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
                stellereum_upgrader::sha256_hex(&plan.sha256)
            ),
        )?;
    }

    let marker_plan = if args.no_wait {
        UpgradePlan::read_marker(&args.marker)?
    } else {
        Some(wait_for_marker(&args.marker, args.wait_timeout, args.poll).map_err(|e| {
            let _ = progress.record("error", &format!("marker {e}"));
            e
        })?)
    };
    if let Some(plan) = &marker_plan {
        progress.record(
            "halt-marker",
            &format!(
                "name={} height={} sha256={}",
                plan.name,
                plan.height,
                stellereum_upgrader::sha256_hex(&plan.sha256)
            ),
        )?;
    }

    let plan = match (marker_plan, rpc_plan) {
        (Some(marker), Some(rpc)) => {
            if !same_plan(&marker, &rpc) {
                return Err(format!(
                    "marker plan (name={}, height={}, sha256={}) disagrees with the committed \
                     RPC plan (name={}, height={}, sha256={}); refusing",
                    marker.name,
                    marker.height,
                    stellereum_upgrader::sha256_hex(&marker.sha256),
                    rpc.name,
                    rpc.height,
                    stellereum_upgrader::sha256_hex(&rpc.sha256),
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
                if args.no_wait {
                    " (--no-wait)"
                } else {
                    ""
                }
            ))
        }
    };
    if plan.sha256 == [0u8; 32] {
        return Err("plan sha256 is all zero; refusing".to_string());
    }

    println!("plan: {}", plan.name);
    println!("halt height: {}", plan.height);
    println!("plan sha256: {}", stellereum_upgrader::sha256_hex(&plan.sha256));
    println!("marker format: {MARKER_HEADER}");

    // 2. Verify the staged bytes BEFORE any filesystem mutation.
    let verified = verify_staged(&args.staged, &plan.sha256).map_err(|e| {
        let _ = progress.record("error", &format!("verify {e}"));
        e
    })?;
    println!(
        "staged binary verified: {} bytes, sha256 {}",
        verified.bytes.len(),
        stellereum_upgrader::sha256_hex(&verified.sha256)
    );
    progress.record(
        "verify",
        &format!(
            "staged={} bytes={} sha256={}",
            args.staged.display(),
            verified.bytes.len(),
            stellereum_upgrader::sha256_hex(&verified.sha256)
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
            stellereum_upgrader::sha256_hex(&verified.sha256)
        ),
    )?;

    let restart = args
        .restart_cmd
        .as_deref()
        .ok_or_else(|| "--apply requires --restart-cmd".to_string())?;
    run_restart_command(restart).map_err(|e| {
        let _ = progress.record("error", &format!("restart {e}"));
        e
    })?;
    println!("restart command completed: {restart}");
    progress.record("restart", &format!("cmd={restart}"))?;
    progress.record("done", "upgrade supervisor completed")?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("stellereum-upgrader: ERROR: {e}");
        std::process::exit(1);
    }
}
