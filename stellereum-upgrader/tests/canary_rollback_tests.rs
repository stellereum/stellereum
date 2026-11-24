use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use stellereum_upgrader::{backup_path_for, HaltMarker};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_stellereum-upgrader")
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "stell-upgrader-canary-{tag}-{}-{nanos}",
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

fn spawn_mock_rpc_server(
    status: &'static str,
    response_json: String,
) -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock health rpc");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking mock rpc");
    let addr = listener.local_addr().expect("local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response_json.len(),
                        response_json
                    );
                    let _ = stream.write_all(reply.as_bytes());
                    let _ = stream.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}"), stop, handle)
}

#[test]
fn cli_apply_healthy_rpc_keeps_new_binary_with_no_rollback() {
    let dir = temp_dir("healthy");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("upgrades/v0.2.0/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");
    let restart_log = dir.join("restarts.log");

    let old_bytes = b"#!/bin/sh\necho old-v0.1.0\n";
    let new_bytes = b"#!/bin/sh\necho new-v0.2.0\n";
    write_exec(&live, old_bytes);
    write_exec(&staged, new_bytes);
    write_marker(&marker, "v0.2.0", 1200, sha256_bytes(new_bytes));

    let (health_url, stop, handle) = spawn_mock_rpc_server(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":1,"result":"0x4b1"}"#.to_string(),
    );

    let mut cmd = Command::new(bin());
    cmd.arg("--marker")
        .arg(&marker)
        .arg("--staged-dir")
        .arg(dir.join("upgrades"))
        .arg("--live")
        .arg(&live)
        .arg("--restart-cmd")
        .arg(format!("echo restarted >> {}", restart_log.display()))
        .arg("--progress")
        .arg(&progress)
        .arg("--health-url")
        .arg(&health_url)
        .arg("--health-wait-secs")
        .arg("3")
        .arg("--poll-ms")
        .arg("25")
        .arg("--rollback-on-fail")
        .arg("--no-wait")
        .arg("--apply");
    if stellereum_upgrader::is_root() {
        cmd.arg("--allow-root");
    }

    let out = cmd.output().expect("run upgrader with healthy rpc");
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    assert!(
        out.status.success(),
        "healthy rpc must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read(&live).expect("read live"), new_bytes);

    let restarts = fs::read_to_string(&restart_log).expect("read restarts");
    assert_eq!(
        restarts.lines().count(),
        1,
        "expected 1 restart: {restarts}"
    );

    let prog = fs::read_to_string(&progress).expect("read progress");
    assert!(prog.contains("step=install"), "{prog}");
    assert!(prog.contains("step=restart"), "{prog}");
    assert!(prog.contains("step=health-check"), "{prog}");
    assert!(prog.contains("step=done"), "{prog}");
    assert!(!prog.contains("step=rollback"), "{prog}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_apply_500_rpc_with_rollback_on_fail_restores_prev_binary_and_restarts() {
    let dir = temp_dir("rpc-500");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("upgrades/v0.2.0/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");
    let restart_log = dir.join("restarts.log");

    let old_bytes = b"#!/bin/sh\necho old-good-binary-bytes-0123456789\n";
    let new_bytes = b"#!/bin/sh\necho bad-new-binary-bytes-9876543210\n";
    write_exec(&live, old_bytes);
    write_exec(&staged, new_bytes);
    write_marker(&marker, "v0.2.0", 1200, sha256_bytes(new_bytes));

    let (health_url, stop, handle) = spawn_mock_rpc_server(
        "500 Internal Server Error",
        r#"{"error":"node unhealthy"}"#.to_string(),
    );

    let mut cmd = Command::new(bin());
    cmd.arg("--marker")
        .arg(&marker)
        .arg("--staged")
        .arg(&staged)
        .arg("--live")
        .arg(&live)
        .arg("--restart-cmd")
        .arg(format!("echo restarted >> {}", restart_log.display()))
        .arg("--progress")
        .arg(&progress)
        .arg("--health-url")
        .arg(&health_url)
        .arg("--health-wait-secs")
        .arg("1")
        .arg("--poll-ms")
        .arg("30")
        .arg("--rollback-on-fail")
        .arg("--no-wait")
        .arg("--apply");
    if stellereum_upgrader::is_root() {
        cmd.arg("--allow-root");
    }

    let out = cmd.output().expect("run upgrader with 500 rpc");
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    assert!(
        !out.status.success(),
        "failed health check + rollback must exit non-zero"
    );
    assert_eq!(
        fs::read(&live).expect("read rolled-back live"),
        old_bytes,
        "live binary must match .prev byte-for-byte"
    );
    assert_eq!(
        fs::read(backup_path_for(&live)).expect("read .prev backup"),
        old_bytes
    );

    let restarts = fs::read_to_string(&restart_log).expect("read restarts");
    assert_eq!(
        restarts.lines().count(),
        2,
        "restart command must run for upgrade and rollback: {restarts}"
    );

    let prog = fs::read_to_string(&progress).expect("read progress");
    assert!(prog.contains("step=backup"), "{prog}");
    assert!(prog.contains("step=install"), "{prog}");
    assert!(prog.contains("step=error"), "{prog}");
    assert!(prog.contains("step=rollback"), "{prog}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn cli_apply_unreachable_rpc_with_rollback_on_fail_restores_prev_binary() {
    let dir = temp_dir("rpc-unreachable");
    let live = dir.join("bin/stellereum");
    let staged = dir.join("upgrades/v0.2.0/stellereum");
    let marker = dir.join("data/upgrade-halt.marker");
    let progress = dir.join("data/progress.log");
    let restart_log = dir.join("restarts.log");

    let old_bytes = b"#!/bin/sh\necho old-prev-binary\n";
    let new_bytes = b"#!/bin/sh\necho new-crashing-binary\n";
    write_exec(&live, old_bytes);
    write_exec(&staged, new_bytes);
    write_marker(&marker, "v0.2.0", 1200, sha256_bytes(new_bytes));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let dead_url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);

    let mut cmd = Command::new(bin());
    cmd.arg("--marker")
        .arg(&marker)
        .arg("--staged")
        .arg(&staged)
        .arg("--live")
        .arg(&live)
        .arg("--restart-cmd")
        .arg(format!("echo restarted >> {}", restart_log.display()))
        .arg("--progress")
        .arg(&progress)
        .arg("--health-url")
        .arg(&dead_url)
        .arg("--health-wait-secs")
        .arg("1")
        .arg("--poll-ms")
        .arg("30")
        .arg("--rollback-on-fail")
        .arg("--no-wait")
        .arg("--apply");
    if stellereum_upgrader::is_root() {
        cmd.arg("--allow-root");
    }

    let out = cmd.output().expect("run upgrader with unreachable rpc");
    assert!(!out.status.success(), "unreachable health check must fail");
    assert_eq!(fs::read(&live).expect("read restored live"), old_bytes);

    let restarts = fs::read_to_string(&restart_log).expect("read restarts");
    assert_eq!(restarts.lines().count(), 2, "{restarts}");

    let prog = fs::read_to_string(&progress).expect("read progress");
    assert!(prog.contains("step=rollback"), "{prog}");

    fs::remove_dir_all(&dir).ok();
}
