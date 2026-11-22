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
