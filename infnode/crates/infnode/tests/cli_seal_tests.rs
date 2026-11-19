//! CLI owner-sealed storage wiring (W9-3 leftover).
//!
//! `infnode storage-put` / `storage-get` used to write the public
//! content-derived-key format (data key in the manifest). This suite pins the
//! new contract: `storage-put` seals to an owner ML-KEM-768 ek (flag, or the
//! node's own key when omitted), the manifest carries `seal` + `key_box` and
//! NEVER a plaintext `key`, and only the matching owner seed can read it back.

use infnode::config::{self, NodeConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::mailbox::MailKeys;
use infnode::node::BLOB_SEAL_V1;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-cli-seal-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

fn cfg(name: &str) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    }
}

fn setup(tag: &str) -> PathBuf {
    let dir = tmpdir(tag);
    NodeKeys::generate().save(&dir.join("keys")).expect("keys");
    let _ = PqKeys::load_or_generate(&dir.join("keys")).expect("pq keys");
    config::save(&dir.join("node.yaml"), &cfg(tag)).expect("config");
    dir
}

fn infnode_bin() -> &'static str {
    env!("CARGO_BIN_EXE_infnode")
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(infnode_bin())
        .args(args)
        .output()
        .expect("spawn infnode");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn cli_storage_put_seals_to_the_owner_key_and_get_requires_it() {
    let dir = setup("roundtrip");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("plain.txt");
    let payload = b"owner-sealed CLI payload -- not decryptable by storage peers";
    std::fs::write(&src, payload).expect("input");

    let owner = MailKeys::generate();
    let owner_ek = hex::encode(&owner.kem_ek);
    let owner_seed = hex::encode(owner.kem_seed);

    let (ok, stdout, stderr) = run(&[
        "storage-put",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "secret.txt",
        "--file",
        src.to_str().unwrap(),
        "--owner-ek",
        &owner_ek,
        "--owner-key",
        &owner_seed,
    ]);
    assert!(ok, "storage-put failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("sealed=owner"),
        "put must report owner sealing: {stdout}"
    );
    assert!(
        stdout.contains("replicas=1"),
        "put must report the real replica count (this node stores the bucket): {stdout}"
    );

    // The manifest on disk must be owner-sealed: seal marker + key_box, and
    // no plaintext data key.
    let kv_path = dir.join("kv.json");
    let kv = std::fs::read_to_string(&kv_path).expect("kv.json flushed by CLI");
    assert!(
        kv.contains(BLOB_SEAL_V1),
        "manifest must carry the {BLOB_SEAL_V1} seal marker"
    );
    assert!(
        kv.contains("key_box"),
        "data key must be wrapped to the owner key"
    );
    assert!(
        !kv.contains("\"key\":\""),
        "owner-sealed manifest must not contain a plaintext data key"
    );

    // Owner can read it back.
    let out = dir.join("out.txt");
    let (ok, stdout, stderr) = run(&[
        "storage-get",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "secret.txt",
        "--out",
        out.to_str().unwrap(),
        "--owner-key",
        &owner_seed,
    ]);
    assert!(ok, "storage-get failed: {stdout}\n{stderr}");
    assert_eq!(std::fs::read(&out).expect("output"), payload);

    // A different owner key cannot open it (and the plain fallback must not
    // silently return the sealed bytes).
    let attacker = MailKeys::generate();
    let attacker_seed = hex::encode(attacker.kem_seed);
    let out2 = dir.join("attacker.txt");
    let (_ok, stdout, _stderr) = run(&[
        "storage-get",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "secret.txt",
        "--out",
        out2.to_str().unwrap(),
        "--owner-key",
        &attacker_seed,
    ]);
    assert!(
        stdout.contains("owner key refused") || stdout.contains("blob not found"),
        "non-owner get must refuse, got: {stdout}"
    );
    assert!(!Path::new(&out2).exists(), "non-owner must write no output");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_storage_put_defaults_to_the_node_owner_key() {
    let dir = setup("default-key");
    let cfg_path = dir.join("node.yaml");
    let src = dir.join("payload.bin");
    let payload = vec![0xA5u8; 4096];
    std::fs::write(&src, &payload).expect("input");

    let (ok, stdout, stderr) = run(&[
        "storage-put",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "default.bin",
        "--file",
        src.to_str().unwrap(),
    ]);
    assert!(ok, "storage-put failed: {stdout}\n{stderr}");
    assert!(stdout.contains("sealed=owner"), "{stdout}");
    assert!(
        stdout.contains("replicas=1"),
        "default owner path must report its local replica: {stdout}"
    );

    // Even without --owner-key the CLI uses the node's own KEM seed, which
    // matches the default owner ek, so the round trip succeeds.
    let out = dir.join("out.bin");
    let (ok, stdout, stderr) = run(&[
        "storage-get",
        "--config",
        cfg_path.to_str().unwrap(),
        "--to",
        "test",
        "--name",
        "default.bin",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "storage-get failed: {stdout}\n{stderr}");
    assert_eq!(std::fs::read(&out).expect("output"), payload);

    let _ = std::fs::remove_dir_all(&dir);
}
