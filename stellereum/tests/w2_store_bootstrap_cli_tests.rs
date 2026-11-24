//! Wave 2 CLI integration tests for `stellereum store bootstrap`.
//!
//! Exercises the compiled binary (`CARGO_BIN_EXE_stellereum`) end-to-end with
//! offline `.tar.zst` archives, SHA-256 verification, existing-store guards,
//! timestamped backups, `snap*` cleanup, path-traversal refusal, sled lock
//! refusal, and observer vs validator safety-record initialization.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use stellereum::consensus::consensus_chain_id;
use stellereum::safety::{derive_safety_chain_id, operator_safety_init};
use stellereum::storage::{SafetyRecordIdentity, Storage};

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempCleanup(PathBuf);

impl TempCleanup {
    fn new(tag: &str) -> Self {
        let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "stell-w2-store-bootstrap-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha256_file_hex(path: &Path) -> String {
    let bytes = fs::read(path).expect("read archive for sha256");
    hex::encode(Sha256::digest(&bytes))
}

fn create_snapshot_store_dir(store_dir: &Path, foreign_validator: Option<[u8; 32]>) -> [u8; 32] {
    let genesis_root = [0x11u8; 32];
    {
        let storage = Storage::open(store_dir).expect("open source store");
        storage
            .set_meta("genesis_state_root", &genesis_root)
            .expect("set genesis_state_root");
        if let Some(val_pub) = foreign_validator {
            operator_safety_init(&storage, val_pub, 0, None, None, true)
                .expect("init foreign safety record");
        }
    }
    fs::write(store_dir.join("snap.0000000000000001"), b"stale-snap-1")
        .expect("write snap.0000000000000001");
    fs::write(store_dir.join("snap.temp.generating"), b"stale-snap-2")
        .expect("write snap.temp.generating");
    genesis_root
}

fn pack_tar_zst(base_dir: &Path, entries: &[&str], out_archive: &Path) {
    let mut cmd = Command::new("tar");
    cmd.arg("-I")
        .arg("zstd")
        .arg("-cf")
        .arg(out_archive)
        .arg("-C")
        .arg(base_dir);
    for e in entries {
        cmd.arg(e);
    }
    let out = cmd.output().expect("run tar -I zstd -cf");
    assert!(
        out.status.success(),
        "tar -I zstd -cf failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn write_validator_key(keys_dir: &Path, seed: [u8; 32]) -> [u8; 32] {
    fs::create_dir_all(keys_dir).expect("create keys dir");
    let key_path = keys_dir.join("validator.key");
    fs::write(&key_path, hex::encode(seed)).expect("write validator.key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700 dir");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod 0600 file");
    }
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn build_malicious_tar_zst_with_traversal(out_archive: &Path) {
    // Construct a minimal POSIX ustar archive with a "../escape.txt" entry and
    // compress it via `zstd` stdin -> out_archive.
    let mut header = [0u8; 512];
    let name = b"../escape.txt";
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000004\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let csum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    let csum_str = format!("{csum:06o}\0 ");
    header[148..156].copy_from_slice(csum_str.as_bytes());

    let mut payload = [0u8; 512];
    payload[..4].copy_from_slice(b"evil");

    let mut tar_bytes = Vec::with_capacity(512 * 4);
    tar_bytes.extend_from_slice(&header);
    tar_bytes.extend_from_slice(&payload);
    tar_bytes.extend_from_slice(&[0u8; 1024]);

    let mut child = Command::new("zstd")
        .args(["-q", "-f", "-o"])
        .arg(out_archive)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn zstd");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(&tar_bytes)
        .expect("write tar bytes to zstd");
    let status = child.wait().expect("wait zstd");
    assert!(status.success(), "zstd failed");
}

#[test]
fn help_and_dry_run_validate_flags_without_mutating_disk() {
    let help = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args(["store", "bootstrap", "--help"])
        .output()
        .expect("run store bootstrap --help");
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    for flag in [
        "--data-dir",
        "--keys-dir",
        "--shard",
        "--snapshot-url",
        "--sha256-url",
        "--require-sha256",
        "--archive",
        "--expected-sha256",
        "--refresh-if-stale",
        "--force",
        "--no-backup",
        "--i-fenced-all-signers",
        "--observer",
        "--dry-run",
        "--json",
    ] {
        assert!(help_text.contains(flag), "missing flag {flag} in --help");
    }

    let tmp = TempCleanup::new("dry-run");
    let src_root = tmp.path().join("src");
    let src_store = src_root.join("store");
    create_snapshot_store_dir(&src_store, Some([0x99u8; 32]));
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);
    let sha = sha256_file_hex(&archive);

    let data_dir = tmp.path().join("target_data");
    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--expected-sha256",
            &sha,
            "--observer",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run store bootstrap --dry-run --json");
    assert!(
        out.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !data_dir.exists(),
        "--dry-run must not create or mutate data_dir"
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("dry-run stdout must be valid JSON");
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(parsed["dry_run"], serde_json::json!(true));
    assert_eq!(parsed["mode"], serde_json::json!("observer"));
    assert_eq!(
        parsed["sha256"]["status"],
        serde_json::json!("planned_pinned")
    );
    assert_eq!(parsed["sha256"]["expected"], serde_json::json!(sha));
}

#[test]
fn refuses_existing_store_without_refresh_if_stale_or_force() {
    let tmp = TempCleanup::new("refuse-existing");
    let src_root = tmp.path().join("src");
    create_snapshot_store_dir(&src_root.join("store"), None);
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);

    let data_dir = tmp.path().join("data");
    let existing_store = data_dir.join("store");
    fs::create_dir_all(&existing_store).unwrap();
    fs::write(existing_store.join("marker.txt"), b"do-not-touch").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--observer",
        ])
        .output()
        .expect("run store bootstrap on existing store");
    assert!(
        !out.status.success(),
        "existing store without --refresh-if-stale/--force must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--refresh-if-stale") || stderr.contains("--force"),
        "expected refusal guidance, got: {stderr}"
    );
    assert_eq!(
        fs::read(existing_store.join("marker.txt")).unwrap(),
        b"do-not-touch"
    );
}

#[test]
fn bad_expected_sha256_fails_closed_before_touching_existing_store() {
    let tmp = TempCleanup::new("bad-sha256");
    let src_root = tmp.path().join("src");
    create_snapshot_store_dir(&src_root.join("store"), None);
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);
    let real_sha = sha256_file_hex(&archive);
    let bad_sha = if let Some(rest) = real_sha.strip_prefix('0') {
        format!("1{rest}")
    } else {
        format!("0{}", &real_sha[1..])
    };

    let data_dir = tmp.path().join("data");
    let existing_store = data_dir.join("store");
    fs::create_dir_all(&existing_store).unwrap();
    fs::write(existing_store.join("marker.txt"), b"keep-me").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--expected-sha256",
            &bad_sha,
            "--force",
            "--observer",
        ])
        .output()
        .expect("run store bootstrap with bad sha256");
    assert!(
        !out.status.success(),
        "bad --expected-sha256 must fail closed"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("SHA-256 mismatch"),
        "expected SHA-256 mismatch error, got: {stderr}"
    );
    assert_eq!(
        fs::read(existing_store.join("marker.txt")).unwrap(),
        b"keep-me",
        "existing store must remain untouched on SHA-256 mismatch"
    );
    for entry in fs::read_dir(&data_dir).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().contains("bak-bootstrap"),
            "no backup must be created when SHA-256 fails"
        );
    }
}

#[test]
fn offline_archive_observer_extracts_strips_snap_and_clears_foreign_safety() {
    let tmp = TempCleanup::new("observer-ok");
    let src_root = tmp.path().join("src");
    let genesis_root = create_snapshot_store_dir(&src_root.join("store"), Some([0x99u8; 32]));
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);
    let sha = sha256_file_hex(&archive);

    let data_dir = tmp.path().join("data");
    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--expected-sha256",
            &sha,
            "--observer",
            "--json",
        ])
        .output()
        .expect("run store bootstrap --observer --json");
    assert!(
        out.status.success(),
        "observer bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(parsed["dry_run"], serde_json::json!(false));
    assert_eq!(parsed["mode"], serde_json::json!("observer"));
    assert_eq!(parsed["sha256"]["status"], serde_json::json!("verified"));
    assert_eq!(parsed["sha256"]["actual"], serde_json::json!(sha));
    assert_eq!(parsed["snap_files_removed"], serde_json::json!(2));
    assert_eq!(parsed["safety_reset"]["ran"], serde_json::json!(true));
    assert_eq!(
        parsed["safety_reset"]["removed_existing_record"],
        serde_json::json!(true)
    );
    assert_eq!(parsed["safety_init"]["ran"], serde_json::json!(false));

    let target_store = data_dir.join("store");
    assert!(!target_store.join("snap.0000000000000001").exists());
    assert!(!target_store.join("snap.temp.generating").exists());

    let storage = Storage::open(&target_store).expect("open bootstrapped observer store");
    assert_eq!(
        storage.get_meta("genesis_state_root").unwrap(),
        Some(genesis_root.to_vec())
    );
    let safety_tree = storage
        .safety_record_tree_for_test()
        .expect("open safety tree");
    assert!(
        safety_tree.is_empty(),
        "observer bootstrap must clear foreign safety_record_v1"
    );
}

#[test]
fn refresh_creates_timestamped_backup_and_no_backup_skips_it() {
    let tmp = TempCleanup::new("backup");
    let src_root = tmp.path().join("src");
    create_snapshot_store_dir(&src_root.join("store"), None);
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);

    let data_dir = tmp.path().join("data");
    let existing_store = data_dir.join("store");
    fs::create_dir_all(&existing_store).unwrap();
    fs::write(existing_store.join("old_marker.txt"), b"old-store-data").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--refresh-if-stale",
            "--observer",
            "--json",
        ])
        .output()
        .expect("run store bootstrap --refresh-if-stale");
    assert!(
        out.status.success(),
        "refresh bootstrap failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(parsed["replaced_existing"], serde_json::json!(true));
    let backup_str = parsed["backup_path"]
        .as_str()
        .expect("backup_path must be populated");
    let backup_path = PathBuf::from(backup_str);
    assert!(backup_path.is_dir(), "backup dir must exist");
    assert_eq!(
        fs::read(backup_path.join("old_marker.txt")).unwrap(),
        b"old-store-data"
    );
    assert!(!existing_store.join("old_marker.txt").exists());

    // Now test --force --no-backup: no second backup dir is created.
    let out2 = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--force",
            "--no-backup",
            "--observer",
            "--json",
        ])
        .output()
        .expect("run store bootstrap --force --no-backup");
    assert!(out2.status.success());
    let parsed2: serde_json::Value = serde_json::from_slice(&out2.stdout).expect("valid JSON");
    assert_eq!(parsed2["backup_path"], serde_json::Value::Null);
    let backup_count = fs::read_dir(&data_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .ok()
                .map(|d| d.file_name().to_string_lossy().contains("bak-bootstrap"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(backup_count, 1, "--no-backup must not create a new backup");
}

#[test]
fn validator_mode_requires_fencing_and_initializes_safety_record() {
    let tmp = TempCleanup::new("validator");
    let src_root = tmp.path().join("src");
    let genesis_root = create_snapshot_store_dir(&src_root.join("store"), Some([0x99u8; 32]));
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);
    let sha = sha256_file_hex(&archive);

    let keys_dir = tmp.path().join("keys");
    let val_pub = write_validator_key(&keys_dir, [0x42u8; 32]);
    let data_dir = tmp.path().join("data");

    // 1. Without --i-fenced-all-signers (and without --observer), must refuse.
    let refused = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--keys-dir",
            keys_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--expected-sha256",
            &sha,
        ])
        .output()
        .expect("run validator store bootstrap without fencing");
    assert!(!refused.status.success());
    let refused_err = String::from_utf8_lossy(&refused.stderr);
    assert!(refused_err.contains("--i-fenced-all-signers"));
    assert!(refused_err.contains("--observer"));
    assert!(!data_dir.join("store").exists());

    // 2. With --i-fenced-all-signers, clears foreign safety and initializes local validator record.
    let ok = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--keys-dir",
            keys_dir.to_str().unwrap(),
            "--shard",
            "0",
            "--archive",
            archive.to_str().unwrap(),
            "--expected-sha256",
            &sha,
            "--i-fenced-all-signers",
            "--json",
        ])
        .output()
        .expect("run validator store bootstrap with fencing");
    assert!(
        ok.status.success(),
        "validator bootstrap failed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&ok.stdout).expect("valid JSON");
    assert_eq!(parsed["mode"], serde_json::json!("validator"));
    assert_eq!(parsed["safety_reset"]["ran"], serde_json::json!(true));
    assert_eq!(parsed["safety_init"]["ran"], serde_json::json!(true));
    assert_eq!(
        parsed["safety_init"]["validator"],
        serde_json::json!(hex::encode(val_pub))
    );
    assert_eq!(parsed["safety_init"]["generation"], serde_json::json!(1));

    let storage = Storage::open(&data_dir.join("store")).expect("open validator store");
    let identity = SafetyRecordIdentity {
        validator: val_pub,
        chain: derive_safety_chain_id(consensus_chain_id(), &genesis_root),
        shard: 0,
    };
    let rec = storage
        .safety_record_store(identity)
        .expect("safety store")
        .load()
        .expect("load record")
        .expect("safety record initialized");
    assert_eq!(rec.generation, 1);
}

#[test]
fn nested_data_store_normalizes_and_traversal_archive_is_rejected() {
    let tmp = TempCleanup::new("layout-and-traversal");

    // 1. Nested data/store layout normalizes cleanly.
    let src_parent = tmp.path().join("src_parent");
    let nested_store = src_parent.join("data").join("store");
    let genesis_root = create_snapshot_store_dir(&nested_store, None);
    let nested_archive = tmp.path().join("nested.tar.zst");
    pack_tar_zst(&src_parent, &["data/store"], &nested_archive);

    let data_dir = tmp.path().join("data");
    let ok = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            nested_archive.to_str().unwrap(),
            "--observer",
        ])
        .output()
        .expect("run nested store bootstrap");
    assert!(
        ok.status.success(),
        "nested data/store bootstrap failed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let st = Storage::open(&data_dir.join("store")).expect("open normalized store");
    assert_eq!(
        st.get_meta("genesis_state_root").unwrap(),
        Some(genesis_root.to_vec())
    );
    drop(st);

    // 2. Archive containing path traversal ("../escape.txt") is rejected before touching store.
    let bad_archive = tmp.path().join("evil.tar.zst");
    build_malicious_tar_zst_with_traversal(&bad_archive);
    let bad = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            bad_archive.to_str().unwrap(),
            "--force",
            "--observer",
        ])
        .output()
        .expect("run traversal archive bootstrap");
    assert!(!bad.status.success(), "traversal archive must be rejected");
    assert!(!tmp.path().join("escape.txt").exists());
}

#[test]
fn live_sled_lock_refuses_bootstrap_cleanly() {
    let tmp = TempCleanup::new("sled-lock");
    let src_root = tmp.path().join("src");
    create_snapshot_store_dir(&src_root.join("store"), None);
    let archive = tmp.path().join("snapshot.tar.zst");
    pack_tar_zst(&src_root, &["store"], &archive);

    let data_dir = tmp.path().join("data");
    let live_store = data_dir.join("store");
    let _held = Storage::open(&live_store).expect("open live store to hold sled lock");

    let out = Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "store",
            "bootstrap",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--archive",
            archive.to_str().unwrap(),
            "--force",
            "--observer",
        ])
        .output()
        .expect("run store bootstrap while sled lock held");
    assert!(
        !out.status.success(),
        "bootstrap must refuse when live sled lock is held"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("lock"),
        "expected lock refusal error, got: {stderr}"
    );
}
