use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

struct FixtureDir(std::path::PathBuf);

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_checks_independent_block_file_and_chain_binding() {
    let path = std::env::temp_dir().join(format!(
        "stellereum-ledger-tool-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let dir = FixtureDir(path);
    let path = dir.0.join("block.bin");
    let block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 42,
        prev_hash: [1; 32],
        state_root: [2; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: [3; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0; 32],
        cnvrf_v3: None,
        order_merkle_root: [0; 32],
        epoch_key_commitment: [0; 32],
        round: 0,
    };
    let bytes = bincode::serialize(&block).unwrap();
    fs::write(&path, &bytes).unwrap();
    let binary = env!("CARGO_BIN_EXE_stellereum-ledger-tool");
    let inspect = Command::new(binary)
        .arg("inspect-block")
        .arg(&path)
        .arg("123")
        .env("STELL_CHAIN_ID", "999")
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let stdout = String::from_utf8(inspect.stdout).unwrap();
    assert!(stdout.contains("no QC, finality"));
    let hash = stdout
        .lines()
        .find_map(|line| line.strip_prefix("computed block hash: "))
        .unwrap();
    let verify = |chain: &str, expected: &str| {
        Command::new(binary)
            .arg("verify-block")
            .arg(&path)
            .arg(chain)
            .arg(expected)
            .output()
            .unwrap()
    };
    assert!(verify("123", hash).status.success());
    assert!(!verify("124", hash).status.success());
    assert!(!verify("123", &"00".repeat(32)).status.success());
    let mut trailing = bytes;
    trailing.push(0);
    fs::write(&path, trailing).unwrap();
    assert!(!verify("123", hash).status.success());
    let oversized = fs::File::create(&path).unwrap();
    oversized.set_len(32 * 1024 * 1024 + 1).unwrap();
    drop(oversized);
    let output = verify("123", hash);
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("exceeds 32 MiB"));
    for command in ["repair", "export"] {
        let output = Command::new(binary)
            .arg(command)
            .arg(&dir.0)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("refused"));
    }
}

#[test]
fn verify_chain_checks_computed_links_and_rejects_bad_inputs() {
    let path = std::env::temp_dir().join(format!(
        "stellereum-ledger-chain-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let dir = FixtureDir(path);
    let files: Vec<_> = (0..3).map(|i| dir.0.join(format!("{i}.bin"))).collect();
    let binary = env!("CARGO_BIN_EXE_stellereum-ledger-tool");
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 42,
        prev_hash: [1; 32],
        state_root: [2; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: [3; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0; 32],
        cnvrf_v3: None,
        order_merkle_root: [0; 32],
        epoch_key_commitment: [0; 32],
        round: 0,
    };
    for file in &files {
        fs::write(file, bincode::serialize(&block).unwrap()).unwrap();
        let output = Command::new(binary)
            .arg("inspect-block")
            .arg(file)
            .arg("123")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let hash = stdout
            .lines()
            .find_map(|line| line.strip_prefix("computed block hash: "))
            .unwrap();
        block.prev_hash = hex::decode(hash).unwrap().try_into().unwrap();
        block.height += 1;
    }
    let run = |format: &str, input: &[&std::path::Path]| {
        Command::new(binary)
            .args(["verify-chain", format, "123"])
            .args(input)
            .output()
            .unwrap()
    };
    let ordered: Vec<_> = files.iter().map(|p| p.as_path()).collect();
    let output = run("current-v1", &ordered);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("parent links to computed block hashes"));
    assert!(stdout.contains("not checked: trusted anchor"));
    assert!(stdout.contains("QC, state, finality"));
    assert!(!run("legacy", &ordered).status.success());
    assert!(!run("current-v1", &[ordered[1], ordered[0]])
        .status
        .success());
    assert!(!run("current-v1", &[ordered[0], ordered[2]])
        .status
        .success());

    let original = fs::read(&files[1]).unwrap();
    let mut changed: Block = bincode::deserialize(&original).unwrap();
    changed.prev_hash[0] ^= 1;
    fs::write(&files[1], bincode::serialize(&changed).unwrap()).unwrap();
    let output = run("current-v1", &ordered);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("parent hash"));
    changed.prev_hash[0] ^= 1;
    changed.shard_id = changed.shard_id.wrapping_add(1);
    fs::write(&files[1], bincode::serialize(&changed).unwrap()).unwrap();
    let output = run("current-v1", &ordered);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("shard differs"));
    fs::write(&files[1], &original).unwrap();

    let missing = dir.0.join("missing.bin");
    assert!(!run("current-v1", &[ordered[0], missing.as_path()])
        .status
        .success());
    let too_many = vec![ordered[0]; 1025];
    let output = run("current-v1", &too_many);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("1024 block limit"));
    let mut trailing = original.clone();
    trailing.push(0);
    fs::write(&files[1], trailing).unwrap();
    assert!(!run("current-v1", &ordered).status.success());
    fs::write(&files[1], &original[..original.len() - 1]).unwrap();
    assert!(!run("current-v1", &ordered).status.success());
    let oversized = fs::File::create(&files[1]).unwrap();
    oversized.set_len(32 * 1024 * 1024 + 1).unwrap();
    drop(oversized);
    let output = run("current-v1", &ordered);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exceeds 32 MiB"));
}

#[test]
fn verify_store_checks_linked_blocks_and_rejects_broken_or_non_store() {
    let path = std::env::temp_dir().join(format!(
        "stellereum-ledger-store-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let dir = FixtureDir(path);
    let binary = env!("CARGO_BIN_EXE_stellereum-ledger-tool");
    let chain_id = stellereum::consensus::consensus_chain_id();

    let make_block = |height: u64, prev_hash: [u8; 32]| Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root: [height as u8 + 1; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 100 + height,
        proposer: [3; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0; 32],
        cnvrf_v3: None,
        order_merkle_root: [0; 32],
        epoch_key_commitment: [0; 32],
        round: 0,
    };

    let store_dir = dir.0.join("store");
    let h2 = {
        let storage = stellereum::storage::Storage::open(&store_dir).unwrap();
        let b0 = make_block(0, [0; 32]);
        let h0 = storage.put_block(&b0).unwrap();
        let b1 = make_block(1, h0);
        let h1 = storage.put_block(&b1).unwrap();
        let b2 = make_block(2, h1);
        let h2 = storage.put_block(&b2).unwrap();
        storage.set_finalized(2, &h2).unwrap();
        storage.flush().unwrap();
        h2
    };

    let output = Command::new(binary)
        .arg("verify-store")
        .arg(&store_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("heights 0..=2"));
    assert!(stdout.contains("finalized height: 2"));
    assert!(stdout.contains(&hex::encode(h2)));

    // Wrong chain-id must fail cleanly.
    let wrong_chain = Command::new(binary)
        .arg("verify-store")
        .arg(&store_dir)
        .arg((chain_id + 1).to_string())
        .output()
        .unwrap();
    assert!(!wrong_chain.status.success());

    // Non-store directory must fail cleanly without creating `db`.
    let empty_dir = dir.0.join("not-a-store");
    fs::create_dir(&empty_dir).unwrap();
    let non_store = Command::new(binary)
        .arg("verify-store")
        .arg(&empty_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!non_store.status.success());
    assert!(!empty_dir.join("db").exists());

    let missing_dir = dir.0.join("missing");
    let missing = Command::new(binary)
        .arg("verify-store")
        .arg(&missing_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(!missing_dir.exists());

    // Broken prev_hash linkage must fail cleanly.
    let broken_dir = dir.0.join("broken-store");
    {
        let storage = stellereum::storage::Storage::open(&broken_dir).unwrap();
        let b0 = make_block(0, [0; 32]);
        let h0 = storage.put_block(&b0).unwrap();
        let b1 = make_block(1, h0);
        let _h1 = storage.put_block(&b1).unwrap();
        let b2 = make_block(2, [0xff; 32]);
        let h2 = storage.put_block(&b2).unwrap();
        storage.set_finalized(2, &h2).unwrap();
        storage.flush().unwrap();
    }
    let broken = Command::new(binary)
        .arg("verify-store")
        .arg(&broken_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!broken.status.success());
    assert!(String::from_utf8_lossy(&broken.stderr).contains("broken prev_hash"));
}

fn temp_fixture_dir(prefix: &str) -> FixtureDir {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    FixtureDir(path)
}

fn test_block(height: u64, prev_hash: [u8; 32]) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root: [height as u8 + 1; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 100 + height,
        proposer: [3; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0; 32],
        cnvrf_v3: None,
        order_merkle_root: [0; 32],
        epoch_key_commitment: [0; 32],
        round: 0,
    }
}

fn snapshot_dir_contents(
    root: &std::path::Path,
) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn walk(
        base: &std::path::Path,
        dir: &std::path::Path,
        out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path.strip_prefix(base).unwrap().to_path_buf();
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(
                !meta.file_type().is_symlink(),
                "unexpected symlink in store snapshot: {}",
                path.display()
            );
            if meta.is_dir() {
                walk(base, &path, out);
            } else {
                out.insert(rel, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[cfg(unix)]
#[test]
fn verify_store_refuses_symlinks() {
    let dir = temp_fixture_dir("stellereum-ledger-symlink");
    let binary = env!("CARGO_BIN_EXE_stellereum-ledger-tool");
    let chain_id = stellereum::consensus::consensus_chain_id();

    let real_store = dir.0.join("real-store");
    {
        let storage = stellereum::storage::Storage::open(&real_store).unwrap();
        let b0 = test_block(0, [0; 32]);
        let h0 = storage.put_block(&b0).unwrap();
        storage.set_finalized(0, &h0).unwrap();
        storage.flush().unwrap();
    }

    let sym_store = dir.0.join("sym-store");
    std::os::unix::fs::symlink(&real_store, &sym_store).unwrap();
    let out = Command::new(binary)
        .arg("verify-store")
        .arg(&sym_store)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));

    let sym_db_store = dir.0.join("sym-db-store");
    fs::create_dir(&sym_db_store).unwrap();
    std::os::unix::fs::symlink(real_store.join("db"), sym_db_store.join("db")).unwrap();
    let out = Command::new(binary)
        .arg("verify-store")
        .arg(&sym_db_store)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));

    let sym_blobs_store = dir.0.join("sym-blobs-store");
    fs::create_dir(&sym_blobs_store).unwrap();
    fs::copy(real_store.join("db"), sym_blobs_store.join("db")).unwrap();
    let outside_blobs = dir.0.join("outside-blobs");
    fs::create_dir(&outside_blobs).unwrap();
    std::os::unix::fs::symlink(&outside_blobs, sym_blobs_store.join("blobs")).unwrap();
    let out = Command::new(binary)
        .arg("verify-store")
        .arg(&sym_blobs_store)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));

    let real_block_file = dir.0.join("block.bin");
    fs::write(
        &real_block_file,
        bincode::serialize(&test_block(0, [0; 32])).unwrap(),
    )
    .unwrap();
    let sym_block_file = dir.0.join("sym-block.bin");
    std::os::unix::fs::symlink(&real_block_file, &sym_block_file).unwrap();
    let out = Command::new(binary)
        .arg("inspect-block")
        .arg(&sym_block_file)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));
}

#[test]
fn verify_store_leaves_target_store_untouched_and_refuses_active_lock() {
    let dir = temp_fixture_dir("stellereum-ledger-nonmutating");
    let binary = env!("CARGO_BIN_EXE_stellereum-ledger-tool");
    let chain_id = stellereum::consensus::consensus_chain_id();

    let store_dir = dir.0.join("store");
    {
        let storage = stellereum::storage::Storage::open(&store_dir).unwrap();
        let b0 = test_block(0, [0; 32]);
        let h0 = storage.put_block(&b0).unwrap();
        let b1 = test_block(1, h0);
        let h1 = storage.put_block(&b1).unwrap();
        let b2 = test_block(2, h1);
        let h2 = storage.put_block(&b2).unwrap();
        storage.set_finalized(2, &h2).unwrap();
        storage.set_receipt_index_ready_for_test(false).unwrap();
        storage.flush().unwrap();
    }

    let before = snapshot_dir_contents(&store_dir);

    let out = Command::new(binary)
        .arg("verify-store")
        .arg(&store_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = snapshot_dir_contents(&store_dir);
    assert_eq!(
        before, after,
        "verify-store must leave the target store directory byte-for-byte untouched"
    );

    let lock_path = dir.0.join(".node.lock");
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    lock_file.try_lock().unwrap();

    let locked_out = Command::new(binary)
        .arg("verify-store")
        .arg(&store_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!locked_out.status.success());
    assert!(String::from_utf8_lossy(&locked_out.stderr).contains("node lock"));

    drop(lock_file);

    let in_place_out = Command::new(binary)
        .args(["verify-store", "--in-place"])
        .arg(&store_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(
        in_place_out.status.success(),
        "{}",
        String::from_utf8_lossy(&in_place_out.stderr)
    );
}

#[test]
fn verify_store_walks_retained_headers_across_pruned_boundary_and_rejects_broken_link() {
    let dir = temp_fixture_dir("stellereum-ledger-pruned-headers");
    let binary = env!("CARGO_BIN_EXE_stellereum-ledger-tool");
    let chain_id = stellereum::consensus::consensus_chain_id();

    let store_dir = dir.0.join("pruned-store");
    {
        let storage = stellereum::storage::Storage::open(&store_dir).unwrap();
        let b0 = test_block(0, [0; 32]);
        let h0 = storage.put_block(&b0).unwrap();
        let b1 = test_block(1, h0);
        let h1 = storage.put_block(&b1).unwrap();
        let b2 = test_block(2, h1);
        let h2 = storage.put_block(&b2).unwrap();
        let b3 = test_block(3, h2);
        let h3 = storage.put_block(&b3).unwrap();
        storage.set_finalized(3, &h3).unwrap();
        storage.prune_blocks_below(3).unwrap();
        assert_eq!(storage.block_count().unwrap(), 2);
        assert_eq!(storage.header_count().unwrap(), 4);
        storage.flush().unwrap();
    }

    let ok_out = Command::new(binary)
        .arg("verify-store")
        .arg(&store_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(
        ok_out.status.success(),
        "{}",
        String::from_utf8_lossy(&ok_out.stderr)
    );
    let stdout = String::from_utf8(ok_out.stdout).unwrap();
    assert!(stdout.contains("heights 2..=3"));
    assert!(stdout.contains("heights 0..=1"));

    {
        let storage = stellereum::storage::Storage::open(&store_dir).unwrap();
        let alt_b0 = test_block(0, [0xaa; 32]);
        storage
            .put_header(&stellereum::storage::BlockHeaderRecord::of(&alt_b0))
            .unwrap();
        storage
            .put_header_v2(&stellereum::storage::BlockHeaderRecordV2::of(&alt_b0))
            .unwrap();
        storage.flush().unwrap();
    }

    let broken_out = Command::new(binary)
        .arg("verify-store")
        .arg(&store_dir)
        .arg(chain_id.to_string())
        .output()
        .unwrap();
    assert!(!broken_out.status.success());
    assert!(String::from_utf8_lossy(&broken_out.stderr).contains("broken prev_hash"));
}
