use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use stellereum_upgrader::{format_sha256_hex, HaltMarker};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_stellereum-upgrader")
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "stell-upgrader-it-{tag}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod dir");
    dir
}

fn write_exec(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).expect("chmod parent");
    }
    fs::write(path, bytes).expect("write exec");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod exec");
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn write_marker(path: &Path, name: &str, height: u64, sha: [u8; 32]) {
    let marker = HaltMarker {
        height,
        halted_at_height: height,
        plan_name: name.to_string(),
        plan_sha256: sha,
        target_version: name.to_string(),
        running_version: "0.1.0".to_string(),
        halted_unix: 1763500000,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create marker parent");
    }
    fs::write(path, marker.render()).expect("write marker");
}

fn spawn_single_rpc_server(response_json: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rpc");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_json.len(),
                response_json
            );
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn cli_print_systemd_outputs_both_modes() {
    let out = Command::new(bin())
        .arg("--print-systemd")
        .output()
        .expect("run --print-systemd");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--supervise"), "{stdout}");
    assert!(stdout.contains("RestartPreventExitStatus=42"), "{stdout}");
}

#[test]
fn cli_dry_run_and_apply_watcher_lifecycle() {
    let dir = temp_dir("watcher");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("upgrades/v0.2.0/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");
    let restarted = dir.join("restarted.flag");

    let old_bytes = b"#!/bin/sh\necho old\n";
    let new_bytes = b"#!/bin/sh\necho new\n";
    write_exec(&live, old_bytes);
    write_exec(&staged, new_bytes);
    let new_sha = sha256_bytes(new_bytes);
    write_marker(&marker, "v0.2.0", 1200, new_sha);

    // Dry run (default): verifies and leaves live binary untouched.
    let dry = Command::new(bin())
        .arg("--marker")
        .arg(&marker)
        .arg("--staged-dir")
        .arg(dir.join("upgrades"))
        .arg("--progress")
        .arg(&progress)
        .arg("--no-wait")
        .output()
        .expect("dry run");
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dry_stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(dry_stdout.contains("DRY RUN"), "{dry_stdout}");
    assert_eq!(fs::read(&live).expect("read live"), old_bytes);

    // Apply: swaps live binary and runs restart command.
    let mut apply_cmd = Command::new(bin());
    apply_cmd
        .arg("--marker")
        .arg(&marker)
        .arg("--staged-dir")
        .arg(dir.join("upgrades"))
        .arg("--live")
        .arg(&live)
        .arg("--restart-cmd")
        .arg(format!("touch {}", restarted.display()))
        .arg("--progress")
        .arg(&progress)
        .arg("--no-wait")
        .arg("--apply");
    if stellereum_upgrader::is_root() {
        apply_cmd.arg("--allow-root");
    }
    let apply = apply_cmd.output().expect("apply");
    assert!(
        apply.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert_eq!(fs::read(&live).expect("read swapped live"), new_bytes);
    assert!(restarted.exists(), "restart command must have run");
    let prog_text = fs::read_to_string(&progress).expect("progress");
    assert!(prog_text.contains("step=dry-run"));
    assert!(prog_text.contains("step=install"));
    assert!(prog_text.contains("step=restart"));
    assert!(prog_text.contains("step=done"));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_refuses_rpc_plan_disagreement_via_mock_jsonrpc() {
    let dir = temp_dir("rpc-disagree");
    let staged = dir.join("staged/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");

    let new_bytes = b"upgraded-binary";
    write_exec(&staged, new_bytes);
    let new_sha = sha256_bytes(new_bytes);
    write_marker(&marker, "v0.2.0", 1200, new_sha);

    let different_sha: Vec<u8> = [0x99u8; 32].to_vec();
    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "quorum_bps": 6667,
            "next_id": 2,
            "applied": {
                "upgrade_plan": {
                    "name": "v0.2.0",
                    "height": 1200,
                    "sha256": different_sha,
                }
            }
        }
    })
    .to_string();
    let (url, handle) = spawn_single_rpc_server(rpc_body);

    let out = Command::new(bin())
        .arg("--marker")
        .arg(&marker)
        .arg("--rpc")
        .arg(&url)
        .arg("--staged")
        .arg(&staged)
        .arg("--progress")
        .arg(&progress)
        .arg("--no-wait")
        .output()
        .expect("run upgrader with disagreeing rpc");
    let _ = handle.join();

    assert!(
        !out.status.success(),
        "must refuse when marker and RPC disagree"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("disagrees"), "{stderr}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_uses_marker_when_rpc_is_already_down_after_halt() {
    let dir = temp_dir("rpc-down");
    let staged = dir.join("staged/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");

    let new_bytes = b"upgraded-binary";
    write_exec(&staged, new_bytes);
    write_marker(&marker, "v0.2.0", 1200, sha256_bytes(new_bytes));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let dead_url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);

    let out = Command::new(bin())
        .arg("--marker")
        .arg(&marker)
        .arg("--rpc")
        .arg(&dead_url)
        .arg("--staged")
        .arg(&staged)
        .arg("--progress")
        .arg(&progress)
        .arg("--no-wait")
        .output()
        .expect("run upgrader with dead rpc and valid marker");

    assert!(
        out.status.success(),
        "marker must drive dry-run when halted node RPC is down: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format_sha256_hex(&sha256_bytes(new_bytes))));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_supervise_dry_run_catches_exit_42_without_replacing() {
    let dir = temp_dir("sup-dry");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("staged/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");

    let new_script = b"#!/bin/sh\nexit 0\n";
    let new_sha = sha256_bytes(new_script);
    let new_sha_hex = format_sha256_hex(&new_sha);
    let old_script = format!(
        "#!/bin/sh\n\
         mkdir -p \"{}\"\n\
         cat > \"{}\" <<EOF\n\
stell-upgrade-halt v1\n\
height=450\n\
halted_at_height=450\n\
plan_name=v0.3.0\n\
plan_sha256={new_sha_hex}\n\
target_version=v0.3.0\n\
running_version=0.2.0\n\
halted_unix=1763500000\n\
EOF\n\
         exit 42\n",
        marker.parent().expect("parent").display(),
        marker.display(),
    );

    write_exec(&live, old_script.as_bytes());
    write_exec(&staged, new_script);

    let out = Command::new(bin())
        .arg("--supervise")
        .arg("--live")
        .arg(&live)
        .arg("--staged")
        .arg(&staged)
        .arg("--marker")
        .arg(&marker)
        .arg("--progress")
        .arg(&progress)
        .arg("--poll-ms")
        .arg("20")
        .arg("--wait-timeout")
        .arg("5")
        .output()
        .expect("run supervise dry-run");

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DRY RUN"), "{stdout}");
    assert_eq!(
        fs::read(&live).expect("live untouched"),
        old_script.as_bytes()
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_supervise_apply_catches_exit_42_swaps_and_respawns_with_supermajority_env() {
    let dir = temp_dir("sup-apply");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("upgrades/v0.3.0/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");
    let record = dir.join("respawn.env");

    let new_script = format!(
        "#!/bin/sh\n\
         printf 'args=%s\\nsupermajority=%s\\nversion=%s\\n' \"$*\" \"$STELL_WAIT_SUPERMAJORITY\" \"$STELL_UPGRADE_VERSION\" > \"{}\"\n\
         exit 0\n",
        record.display(),
    );
    let new_sha = sha256_bytes(new_script.as_bytes());
    let new_sha_hex = format_sha256_hex(&new_sha);
    let old_script = format!(
        "#!/bin/sh\n\
         mkdir -p \"{}\"\n\
         cat > \"{}\" <<EOF\n\
stell-upgrade-halt v1\n\
height=450\n\
halted_at_height=451\n\
plan_name=v0.3.0\n\
plan_sha256={new_sha_hex}\n\
target_version=v0.3.0\n\
running_version=0.2.0\n\
halted_unix=1763500000\n\
EOF\n\
         exit 42\n",
        marker.parent().expect("parent").display(),
        marker.display(),
    );

    write_exec(&live, old_script.as_bytes());
    write_exec(&staged, new_script.as_bytes());

    let mut cmd = Command::new(bin());
    cmd.arg("--supervise")
        .arg("--live")
        .arg(&live)
        .arg("--staged-dir")
        .arg(dir.join("upgrades"))
        .arg("--marker")
        .arg(&marker)
        .arg("--progress")
        .arg(&progress)
        .arg("--set-wait-supermajority")
        .arg("--poll-ms")
        .arg("20")
        .arg("--wait-timeout")
        .arg("5")
        .arg("--apply");
    if stellereum_upgrader::is_root() {
        cmd.arg("--allow-root");
    }
    cmd.args(["--", "run", "--config", "node.yaml", "--shard", "0"]);

    let out = cmd.output().expect("run supervise apply");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(&live).expect("swapped live"),
        new_script.as_bytes()
    );

    let respawn_text = fs::read_to_string(&record).expect("respawn env record");
    assert!(
        respawn_text.contains("args=run --config node.yaml --shard 0"),
        "{respawn_text}"
    );
    assert!(respawn_text.contains("supermajority=450"), "{respawn_text}");
    assert!(respawn_text.contains("version=v0.3.0"), "{respawn_text}");

    let prog_text = fs::read_to_string(&progress).expect("progress");
    assert!(prog_text.contains("step=halt-exit-42"));
    assert!(prog_text.contains("step=install"));
    assert!(prog_text.contains("step=restart"));
    assert!(prog_text.contains("step=child-exit gen=2 code=0"));

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_supervise_propagates_non_42_failure_without_swapping() {
    let dir = temp_dir("sup-fail");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("staged/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");

    let old_script = b"#!/bin/sh\nexit 7\n";
    let new_script = b"#!/bin/sh\nexit 0\n";
    write_exec(&live, old_script);
    write_exec(&staged, new_script);

    let mut cmd = Command::new(bin());
    cmd.arg("--supervise")
        .arg("--live")
        .arg(&live)
        .arg("--staged")
        .arg(&staged)
        .arg("--marker")
        .arg(&marker)
        .arg("--progress")
        .arg(&progress)
        .arg("--apply");
    if stellereum_upgrader::is_root() {
        cmd.arg("--allow-root");
    }

    let out = cmd.output().expect("run supervise failing child");
    assert!(!out.status.success(), "non-42 failure must fail supervisor");
    assert_eq!(fs::read(&live).expect("live untouched"), old_script);

    fs::remove_dir_all(&dir).ok();
}
