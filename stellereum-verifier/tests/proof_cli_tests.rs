//! End-to-end tests for the offline `verify-snapshot` / `verify-proof`
//! inspection commands and Wave 18C CLI guarantees.
//!
//! Each test spawns the compiled binary through `CARGO_BIN_EXE_...`, writes
//! real `cpat2` proofs, blocks, and snapshot documents to a private temporary
//! directory, and asserts both the exit code and the machine-readable last
//! stdout line. The tampered cases must fail closed: a changed domain preimage
//! or a changed value is not authenticated by the proof, so the verifier must
//! exit 1 with `...=FAIL` (while usage, IO, and JSON/hex parse errors exit 2).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use stellereum::commitment as refc;
use stellereum::cpat2 as refcpat;

use stellereum_verifier::commitment as vc;

/// The binary Cargo builds for this package's `src/main.rs`.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_stellereum-verifier")
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "stellereum-verifier-cli-{label}-{}-{nanos}-{counter}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create the fixture directory");
        Self { path }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.path.join(name);
        std::fs::write(&path, contents).expect("write the fixture");
        path
    }

    fn write_bytes(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.path.join(name);
        std::fs::write(&path, contents).expect("write the binary fixture");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("spawn the verifier binary")
}

fn last_stdout_line(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .last()
        .unwrap_or_default()
        .to_string()
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

fn empty_snapshot() -> refc::CommitmentSnapshot {
    refc::CommitmentSnapshot {
        tokens: stellereum::token::TokenRegistry::new(),
        staking: stellereum::staking::StakingLedger::new(),
        orderbooks: stellereum::orderbook::OrderbookManager::new(),
        order_escrow: HashMap::new(),
        pmm: stellereum::pmm::PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: stellereum::contract::ContractRegistry::new(),
        governance: stellereum::governance::Governance::new(),
        oracle: stellereum::oracle::OracleState::default(),
        session_keys: stellereum::zkml::SessionKeyRegistry::default(),
        bridge: stellereum::bridge::BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    }
}

fn assemble(snapshot: &refc::CommitmentSnapshot) -> vc::VerifierCommitmentSnapshot {
    vc::VerifierCommitmentSnapshot {
        version: refc::COMMITMENT_VERSION,
        tokens: refc::tokens_preimage(&snapshot.tokens),
        staking: refc::staking_preimage(&snapshot.staking),
        pmm: refc::pmm_preimage(
            &snapshot.pmm,
            &snapshot.pmm_usdt_token,
            &snapshot.pmm_treasury,
        ),
        contracts: refc::contracts_preimage(&snapshot.contracts),
        escrow: refc::escrow_preimage(&snapshot.order_escrow),
        governance: refc::governance_preimage(&snapshot.governance),
        oracle: refc::oracle_preimage(&snapshot.oracle),
        session_keys: refc::session_keys_preimage(&snapshot.session_keys),
        books: refc::books_preimage(&snapshot.orderbooks),
        bridge: refc::bridge_preimage(&snapshot.bridge),
        cross_shard: refc::cross_shard_preimage(
            &snapshot.cross_shard_consumed,
            &snapshot.cross_shard_produced,
            &snapshot.cross_shard_completed,
        ),
        xpc: refc::xpc_preimage(&snapshot.cross_shard_xpc),
        zkml: Vec::new(),
        cnvrf: Vec::new(),
        total_minted_nano: 0,
        evm_bindings: Vec::new(),
        pq_registry: Vec::new(),
    }
}

fn snapshot_json_with_prefix(snapshot: &vc::VerifierCommitmentSnapshot, prefix: &str) -> String {
    format!(
        "{{\"version\":{},\"tokens\":\"{prefix}{}\",\"staking\":\"{prefix}{}\",\"pmm\":\"{prefix}{}\",\
         \"contracts\":\"{prefix}{}\",\"escrow\":\"{prefix}{}\",\"governance\":\"{prefix}{}\",\
         \"oracle\":\"{prefix}{}\",\"session_keys\":\"{prefix}{}\",\"books\":\"{prefix}{}\",\
         \"bridge\":\"{prefix}{}\",\"cross_shard\":\"{prefix}{}\",\"xpc\":\"{prefix}{}\",\
         \"zkml\":\"{prefix}{}\",\"cnvrf\":\"{prefix}{}\",\"total_minted_nano\":{},\
         \"evm_bindings\":\"{prefix}{}\",\"pq_registry\":\"{prefix}{}\"}}",
        snapshot.version,
        to_hex(&snapshot.tokens),
        to_hex(&snapshot.staking),
        to_hex(&snapshot.pmm),
        to_hex(&snapshot.contracts),
        to_hex(&snapshot.escrow),
        to_hex(&snapshot.governance),
        to_hex(&snapshot.oracle),
        to_hex(&snapshot.session_keys),
        to_hex(&snapshot.books),
        to_hex(&snapshot.bridge),
        to_hex(&snapshot.cross_shard),
        to_hex(&snapshot.xpc),
        to_hex(&snapshot.zkml),
        to_hex(&snapshot.cnvrf),
        snapshot.total_minted_nano,
        to_hex(&snapshot.evm_bindings),
        to_hex(&snapshot.pq_registry),
    )
}

fn snapshot_json(snapshot: &vc::VerifierCommitmentSnapshot) -> String {
    snapshot_json_with_prefix(snapshot, "")
}

fn proof_json(proof: &refcpat::MerkleProof) -> String {
    let nodes = proof
        .to_nodes()
        .iter()
        .map(|node| format!("\"{node}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{nodes}]")
}

fn accounts_json_with_prefix(leaves: &[([u8; 32], Vec<u8>)], prefix: &str) -> String {
    let items = leaves
        .iter()
        .map(|(key, value)| {
            format!(
                "{{\"key\":\"{prefix}{}\",\"value\":\"{prefix}{}\"}}",
                to_hex(key),
                to_hex(value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn accounts_json(leaves: &[([u8; 32], Vec<u8>)]) -> String {
    accounts_json_with_prefix(leaves, "")
}

fn account_key(index: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&index.to_be_bytes());
    key[8] = 0xA5;
    key[31] = index.wrapping_mul(29) as u8;
    key
}

#[test]
fn verify_proof_cli_accepts_a_real_proof_and_refuses_a_tampered_value() {
    let dir = TempDir::new("proof");
    let key = [0x42u8; 32];
    let value = b"state-root-proof".to_vec();
    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&key, &value);
    let root = trie.root_hash();
    let proof = trie.generate_proof(&key).expect("inclusion proof");
    let proof_path = dir.write("proof.json", &proof_json(&proof));

    let root_hex = to_hex(&root);
    let key_hex = to_hex(&key);
    let value_hex = to_hex(&value);
    let proof_path = proof_path.to_str().expect("utf-8 path");

    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &key_hex,
        "--value",
        &value_hex,
        "--proof",
        proof_path,
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=PASS");

    // The same proof with another value must be refused.
    let tampered = to_hex(b"tampered");
    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &key_hex,
        "--value",
        &tampered,
        "--proof",
        proof_path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=FAIL");
}

#[test]
fn verify_snapshot_cli_accepts_the_commitment_leaf_and_refuses_a_changed_domain() {
    let dir = TempDir::new("snapshot");
    let snapshot = assemble(&empty_snapshot());
    let digest = snapshot.digest();

    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&refc::commitment_key(), &digest);
    trie.insert(&[0x11u8; 32], b"an-account-leaf");
    let root = trie.root_hash();
    let proof = trie
        .generate_proof(&refc::commitment_key())
        .expect("commitment inclusion proof");

    let snapshot_path = dir.write("snapshot.json", &snapshot_json(&snapshot));
    let proof_path = dir.write("proof.json", &proof_json(&proof));
    let root_hex = to_hex(&root);
    let snapshot_path = snapshot_path.to_str().expect("utf-8 path");
    let proof_path = proof_path.to_str().expect("utf-8 path");

    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        snapshot_path,
        "--proof",
        proof_path,
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=PASS");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("digest={}", to_hex(&digest))),
        "the computed digest must be printed"
    );

    // One byte appended to a domain preimage moves the digest away from the
    // leaf the root commits to.
    let mut tampered = snapshot.clone();
    tampered.tokens.push(0x00);
    assert_ne!(tampered.digest(), digest);
    let tampered_path = dir.write("snapshot-tampered.json", &snapshot_json(&tampered));
    let tampered_path = tampered_path.to_str().expect("utf-8 path");
    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        tampered_path,
        "--proof",
        proof_path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=FAIL");
}

#[test]
fn verify_snapshot_full_cli_rebuilds_the_trie_from_account_leaves() {
    let dir = TempDir::new("full");
    let snapshot = assemble(&empty_snapshot());
    let digest = snapshot.digest();

    let mut trie = refcpat::CompressedTrie::new();
    let mut accounts = Vec::new();
    for i in 0..16u64 {
        let key = account_key(i);
        let value = format!("account-record-{i}").into_bytes();
        trie.insert(&key, &value);
        accounts.push((key, value));
    }
    trie.insert(&refc::commitment_key(), &digest);
    let root = trie.root_hash();

    let snapshot_path = dir.write("snapshot.json", &snapshot_json(&snapshot));
    let accounts_path = dir.write("accounts.json", &accounts_json(&accounts));
    let root_hex = to_hex(&root);
    let snapshot_path = snapshot_path.to_str().expect("utf-8 path");
    let accounts_path = accounts_path.to_str().expect("utf-8 path");

    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        snapshot_path,
        "--accounts",
        accounts_path,
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=PASS");

    // One changed account value must change the rebuilt root and be refused.
    let mut tampered_accounts = accounts.clone();
    tampered_accounts[0].1.push(0x00);
    let tampered_path = dir.write("accounts-tampered.json", &accounts_json(&tampered_accounts));
    let tampered_path = tampered_path.to_str().expect("utf-8 path");
    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        snapshot_path,
        "--accounts",
        tampered_path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=FAIL");
}

#[test]
fn verify_proof_absent_cli_accepts_exclusion_and_refuses_tampered() {
    let dir = TempDir::new("absent");
    let present_a = [0x10u8; 32];
    let present_b = [0x20u8; 32];
    let absent_key = [0x30u8; 32];
    let other_absent = [0x40u8; 32];

    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&present_a, b"alpha");
    trie.insert(&present_b, b"beta");
    let root = trie.root_hash();

    let excl_proof = trie
        .generate_exclusion_proof(&absent_key)
        .expect("exclusion proof");
    let excl_path = dir.write("excl.json", &proof_json(&excl_proof));
    let incl_proof = trie.generate_proof(&present_a).expect("inclusion proof");
    let incl_path = dir.write("incl.json", &proof_json(&incl_proof));

    let root_hex = to_hex(&root);
    let absent_hex = to_hex(&absent_key);
    let other_hex = to_hex(&other_absent);
    let present_hex = to_hex(&present_a);
    let excl_path = excl_path.to_str().expect("utf-8 path");
    let incl_path = incl_path.to_str().expect("utf-8 path");

    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &absent_hex,
        "--absent",
        "--proof",
        excl_path,
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=PASS");

    // Different absent key must fail against the proof for `absent_key`.
    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &other_hex,
        "--absent",
        "--proof",
        excl_path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=FAIL");

    // Inclusion proof passed with --absent must be refused.
    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &present_hex,
        "--absent",
        "--proof",
        incl_path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=FAIL");

    // Combining --absent and --value is a usage error (exit 2).
    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &absent_hex,
        "--value",
        "00",
        "--absent",
        "--proof",
        excl_path,
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=FAIL");
}

#[test]
fn verify_snapshot_cli_verifies_all_17_domains() {
    let dir = TempDir::new("snapshot17");
    let empty = empty_snapshot();

    let mut zkml = stellereum::zkml::ZkMlModelRegistry::default();
    let model =
        stellereum::zkml::QuantizedLinearModel::new(vec![stellereum::zkml::QuantizedLayer::new(
            1,
            1,
            vec![2],
            vec![1],
        )]);
    zkml.register([0x11u8; 32], model).expect("register model");

    let mut cnvrf = stellereum::state_engine::CnVrfV3EngineSnapshot::default();
    cnvrf.v3_state.rolling_mix = [0x22u8; 48];
    cnvrf.v3_state.rolling_mix_epoch = 3;

    let mut evm_bindings = stellereum::state_engine::EvmBindingsState::default();
    evm_bindings.bind([0x33u8; 20], [0x44u8; 32]).expect("bind");

    let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x55u8; 32]);
    let mut pq_registry = stellereum::pq_registry::PqRegistry::default();
    pq_registry
        .register_with_seq(
            [0x66u8; 32],
            stellereum::post_quantum::PqScheme::Falcon512,
            kp.public_key().to_vec(),
            1,
            0,
            0,
            true,
        )
        .expect("register pq");

    let total_minted_nano = 9_876_543u64;
    let ref_digest = refc::commitment_digest_with_all_domains(
        &empty,
        &zkml,
        &cnvrf,
        total_minted_nano,
        &evm_bindings,
        &pq_registry,
    );

    let mut snapshot = assemble(&empty);
    snapshot.zkml = refc::zkml_preimage(&zkml);
    snapshot.cnvrf = refc::cnvrf_v3_preimage(&cnvrf);
    snapshot.total_minted_nano = total_minted_nano;
    snapshot.evm_bindings = refc::evm_bindings_preimage(&evm_bindings);
    snapshot.pq_registry = refc::pq_registry_preimage(&pq_registry);
    assert_eq!(snapshot.digest(), ref_digest);

    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&refc::commitment_key(), &ref_digest);
    let root = trie.root_hash();
    let proof = trie
        .generate_proof(&refc::commitment_key())
        .expect("commitment proof");

    let snap_path = dir.write("snapshot17.json", &snapshot_json(&snapshot));
    let proof_path = dir.write("proof17.json", &proof_json(&proof));
    let root_hex = to_hex(&root);
    let snap_path = snap_path.to_str().expect("utf-8 path");
    let proof_path = proof_path.to_str().expect("utf-8 path");

    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        snap_path,
        "--proof",
        proof_path,
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=PASS");

    // Mutating total_minted_nano must fail verification.
    let mut bad = snapshot;
    bad.total_minted_nano += 1;
    let bad_path = dir.write("snapshot17-bad.json", &snapshot_json(&bad));
    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        bad_path.to_str().expect("utf-8 path"),
        "--proof",
        proof_path,
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=FAIL");
}

#[test]
fn verify_block_and_chain_cli_refuse_validator_flags_without_validators() {
    let dir = TempDir::new("flags-no-val");
    let block = stellereum_verifier::wire::Block::default();
    let bytes = stellereum_verifier::wire::encode_block_v7_canonical(&block).expect("encode");
    let block_path = dir.path.join("block.bin");
    std::fs::write(&block_path, &bytes).expect("write block");
    let block_str = block_path.to_str().expect("utf-8 path");

    for flag in ["--verify-txs", "--require-qc", "--require-chain-id"] {
        let out_blk = run(&["verify-block", block_str, flag]);
        assert_eq!(
            out_blk.status.code(),
            Some(2),
            "verify-block {flag} without --validators must exit 2"
        );
        let out_chn = run(&["verify-chain", block_str, flag]);
        assert_eq!(
            out_chn.status.code(),
            Some(2),
            "verify-chain {flag} without --validators must exit 2"
        );
    }
}

#[test]
fn deeply_nested_json_over_64_levels_is_rejected_with_exit_2() {
    let dir = TempDir::new("json-depth");
    let root_hex = to_hex(&[0x11u8; 32]);
    let key_hex = to_hex(&[0x22u8; 32]);

    // 65 nested arrays (> MAX_JSON_DEPTH = 64) must fail cleanly with exit 2.
    let deep_array = format!("{}{}", "[".repeat(65), "]".repeat(65));
    let deep_arr_path = dir.write("deep-array.json", &deep_array);
    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &key_hex,
        "--absent",
        "--proof",
        deep_arr_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(last_stdout_line(&output), "VERIFY_PROOF_RESULT=FAIL");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("JSON nesting depth exceeds 64"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 65 nested objects (> MAX_JSON_DEPTH = 64) must fail cleanly with exit 2.
    let deep_object = format!("{}\"0\"{}", "{\"a\":".repeat(65), "}".repeat(65));
    let deep_obj_path = dir.write("deep-object.json", &deep_object);
    let dummy_proof_path = dir.write("dummy-proof.json", "[]");
    let output = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        deep_obj_path.to_str().expect("utf-8 path"),
        "--proof",
        dummy_proof_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(last_stdout_line(&output), "VERIFY_SNAPSHOT_RESULT=FAIL");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("JSON nesting depth exceeds 64"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Exactly 64 levels is permitted by the depth guard (fails on proof schema instead).
    let depth_64_array = format!("{}{}", "[".repeat(64), "]".repeat(64));
    let depth_64_path = dir.write("depth64.json", &depth_64_array);
    let output = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &key_hex,
        "--absent",
        "--proof",
        depth_64_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("JSON nesting depth exceeds 64"),
        "depth 64 must not trigger depth guard, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn uppercase_0x_prefix_accepted_in_verify_proof_and_verify_snapshot() {
    let dir = TempDir::new("upper-0x");
    let snapshot = assemble(&empty_snapshot());
    let digest = snapshot.digest();

    let key = account_key(7);
    let value = b"uppercase-hex-value".to_vec();
    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&key, &value);
    trie.insert(&refc::commitment_key(), &digest);
    let root = trie.root_hash();
    let key_proof = trie.generate_proof(&key).expect("key proof");

    let key_proof_path = dir.write("key-proof.json", &proof_json(&key_proof));
    let snapshot_path = dir.write(
        "snapshot-0X.json",
        &snapshot_json_with_prefix(&snapshot, "0X"),
    );
    let accounts = vec![(key, value.clone())];
    let accounts_path = dir.write(
        "accounts-0X.json",
        &accounts_json_with_prefix(&accounts, "0X"),
    );

    let root_upper = format!("0X{}", to_hex(&root));
    let key_upper = format!("0X{}", to_hex(&key));
    let value_upper = format!("0X{}", to_hex(&value));

    let out_proof = run(&[
        "verify-proof",
        "--state-root",
        &root_upper,
        "--key",
        &key_upper,
        "--value",
        &value_upper,
        "--proof",
        key_proof_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        out_proof.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out_proof.stderr)
    );
    assert_eq!(last_stdout_line(&out_proof), "VERIFY_PROOF_RESULT=PASS");

    let out_snap = run(&[
        "verify-snapshot",
        "--state-root",
        &root_upper,
        "--snapshot",
        snapshot_path.to_str().expect("utf-8 path"),
        "--accounts",
        accounts_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(
        out_snap.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out_snap.stderr)
    );
    assert_eq!(last_stdout_line(&out_snap), "VERIFY_SNAPSHOT_RESULT=PASS");
}

#[test]
fn exit_codes_distinguish_crypto_failure_from_malformed_json_and_usage() {
    let dir = TempDir::new("exit-codes");
    let key = [0x44u8; 32];
    let value = b"real-value".to_vec();
    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&key, &value);
    let root = trie.root_hash();
    let proof = trie.generate_proof(&key).expect("inclusion proof");

    let proof_path = dir.write("proof.json", &proof_json(&proof));
    let malformed_json_path = dir.write("malformed.json", "{\"broken\": [1, 2,");
    let snapshot_path = dir.write(
        "snapshot.json",
        &snapshot_json(&assemble(&empty_snapshot())),
    );
    let missing_path = dir.path.join("does-not-exist.json");

    let mut wrong_root = root;
    wrong_root[0] ^= 0xFF;
    let wrong_root_hex = to_hex(&wrong_root);
    let root_hex = to_hex(&root);
    let key_hex = to_hex(&key);
    let value_hex = to_hex(&value);

    // 1. Valid inputs, cryptographic mismatch -> exit 1.
    let out_crypto = run(&[
        "verify-proof",
        "--state-root",
        &wrong_root_hex,
        "--key",
        &key_hex,
        "--value",
        &value_hex,
        "--proof",
        proof_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out_crypto.status.code(), Some(1));
    assert_eq!(last_stdout_line(&out_crypto), "VERIFY_PROOF_RESULT=FAIL");

    // 2. Malformed JSON -> exit 2.
    let out_json_proof = run(&[
        "verify-proof",
        "--state-root",
        &root_hex,
        "--key",
        &key_hex,
        "--value",
        &value_hex,
        "--proof",
        malformed_json_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out_json_proof.status.code(), Some(2));
    assert_eq!(
        last_stdout_line(&out_json_proof),
        "VERIFY_PROOF_RESULT=FAIL"
    );

    let out_json_snap = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        malformed_json_path.to_str().expect("utf-8 path"),
        "--proof",
        proof_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out_json_snap.status.code(), Some(2));
    assert_eq!(
        last_stdout_line(&out_json_snap),
        "VERIFY_SNAPSHOT_RESULT=FAIL"
    );

    // 3. Missing file / IO error -> exit 2.
    let out_io = run(&[
        "verify-snapshot",
        "--state-root",
        &root_hex,
        "--snapshot",
        snapshot_path.to_str().expect("utf-8 path"),
        "--proof",
        missing_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out_io.status.code(), Some(2));
    assert_eq!(last_stdout_line(&out_io), "VERIFY_SNAPSHOT_RESULT=FAIL");

    // 4. Bad usage (bad hex / missing flag) -> exit 2.
    let out_usage = run(&[
        "verify-proof",
        "--state-root",
        "not-hex",
        "--key",
        &key_hex,
        "--value",
        &value_hex,
        "--proof",
        proof_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out_usage.status.code(), Some(2));
    assert_eq!(last_stdout_line(&out_usage), "VERIFY_PROOF_RESULT=FAIL");

    let out_missing_args = run(&[
        "verify-snapshot",
        "--snapshot",
        snapshot_path.to_str().expect("utf-8 path"),
        "--proof",
        proof_path.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(out_missing_args.status.code(), Some(2));
    assert_eq!(
        last_stdout_line(&out_missing_args),
        "VERIFY_SNAPSHOT_RESULT=FAIL"
    );
}

#[test]
fn verify_snapshot_block_binds_header_state_root() {
    let dir = TempDir::new("snap-block");
    let snapshot = assemble(&empty_snapshot());
    let digest = snapshot.digest();

    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&refc::commitment_key(), &digest);
    trie.insert(&[0x55u8; 32], b"bound-leaf");
    let root = trie.root_hash();
    let proof = trie
        .generate_proof(&refc::commitment_key())
        .expect("commitment proof");

    let block = stellereum_verifier::wire::Block {
        shard_id: 0,
        height: 10,
        state_root: root,
        timestamp: 1_700_000_010,
        ..stellereum_verifier::wire::Block::default()
    };
    let block_bytes =
        stellereum_verifier::wire::encode_block_v7_canonical(&block).expect("encode block");

    let block_path = dir.write_bytes("block.bin", &block_bytes);
    let bad_block_path = dir.write_bytes("bad-block.bin", b"not-a-valid-v7-block");
    let snapshot_path = dir.write("snapshot.json", &snapshot_json(&snapshot));
    let proof_path = dir.write("proof.json", &proof_json(&proof));

    let block_str = block_path.to_str().expect("utf-8 path");
    let bad_block_str = bad_block_path.to_str().expect("utf-8 path");
    let snapshot_str = snapshot_path.to_str().expect("utf-8 path");
    let proof_str = proof_path.to_str().expect("utf-8 path");

    // 1. --block alone derives state_root from block.header().state_root.
    let out_block_only = run(&[
        "verify-snapshot",
        "--block",
        block_str,
        "--snapshot",
        snapshot_str,
        "--proof",
        proof_str,
    ]);
    assert_eq!(
        out_block_only.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out_block_only.stderr)
    );
    assert_eq!(
        last_stdout_line(&out_block_only),
        "VERIFY_SNAPSHOT_RESULT=PASS"
    );

    // 2. --block + matching --state-root (with 0X prefix) passes.
    let matching_root = format!("0X{}", to_hex(&root));
    let out_both_match = run(&[
        "verify-snapshot",
        "--state-root",
        &matching_root,
        "--block",
        block_str,
        "--snapshot",
        snapshot_str,
        "--proof",
        proof_str,
    ]);
    assert_eq!(out_both_match.status.code(), Some(0));
    assert_eq!(
        last_stdout_line(&out_both_match),
        "VERIFY_SNAPSHOT_RESULT=PASS"
    );

    // 3. --block + mismatching --state-root is refused with exit 1.
    let mut wrong_root = root;
    wrong_root[31] ^= 0x01;
    let out_mismatch = run(&[
        "verify-snapshot",
        "--state-root",
        &to_hex(&wrong_root),
        "--block",
        block_str,
        "--snapshot",
        snapshot_str,
        "--proof",
        proof_str,
    ]);
    assert_eq!(out_mismatch.status.code(), Some(1));
    assert_eq!(
        last_stdout_line(&out_mismatch),
        "VERIFY_SNAPSHOT_RESULT=FAIL"
    );

    // 4. Corrupt --block wire bytes -> exit 1.
    let out_corrupt_block = run(&[
        "verify-snapshot",
        "--block",
        bad_block_str,
        "--snapshot",
        snapshot_str,
        "--proof",
        proof_str,
    ]);
    assert_eq!(out_corrupt_block.status.code(), Some(1));
    assert_eq!(
        last_stdout_line(&out_corrupt_block),
        "VERIFY_SNAPSHOT_RESULT=FAIL"
    );
}

#[test]
fn verify_chain_rejects_shard_id_mismatch_mid_chain() {
    use stellereum::post_quantum::{FalconKeypair, DEFAULT_SALT};
    use stellereum_verifier::block_hash::{compute_block_hash_at, compute_order_merkle_root};
    use stellereum_verifier::consensus::{
        verify_chain as consensus_verify_chain, verify_proposer_signature_with_config,
        CommitteeSchedule, StaticPqKeyRegistry, ValidatorSet,
    };
    use stellereum_verifier::falcon512::{derive_pq_address, FALCON512_SCHEME_ID};
    use stellereum_verifier::wire::{encode_block_v7_canonical, Block as WireBlock, PqScheme};
    use stellereum_verifier::{verify_chain, VerifierConfig};

    let kp = FalconKeypair::generate_from_seed_bytes(&[0x71u8; 32]);
    let val_id = derive_pq_address(FALCON512_SCHEME_ID, kp.public_key(), &DEFAULT_SALT);
    let validators = ValidatorSet::from_list(vec![(val_id, 1_000_000)]);
    let mut keys = StaticPqKeyRegistry::new();
    keys.insert(val_id, PqScheme::Falcon512, kp.public_key().to_vec());

    let config = VerifierConfig::default();
    let sign_block = |block: &mut WireBlock, header_commit_h: u64| {
        block.order_merkle_root = compute_order_merkle_root(&block.transactions);
        let bh = compute_block_hash_at(block, config.chain_id, header_commit_h);
        block.validator_signatures = vec![(block.proposer, kp.sign(&bh))];
    };

    let mut blk0 = WireBlock {
        shard_id: 0,
        height: 1,
        timestamp: 1_700_000_001,
        proposer: val_id,
        ..WireBlock::default()
    };
    sign_block(&mut blk0, config.header_commit_activation_height);
    let h0 = compute_block_hash_at(
        &blk0,
        config.chain_id,
        config.header_commit_activation_height,
    );

    let mut blk1_ok = WireBlock {
        shard_id: 0,
        height: 2,
        prev_hash: h0,
        timestamp: 1_700_000_002,
        proposer: val_id,
        ..WireBlock::default()
    };
    sign_block(&mut blk1_ok, config.header_commit_activation_height);

    let mut blk1_bad_shard = WireBlock {
        shard_id: 1,
        height: 2,
        prev_hash: h0,
        timestamp: 1_700_000_002,
        proposer: val_id,
        ..WireBlock::default()
    };
    sign_block(&mut blk1_bad_shard, config.header_commit_activation_height);

    // Valid contiguous same-shard chain passes both lib and consensus verify_chain.
    verify_chain(
        &[blk0.clone(), blk1_ok.clone()],
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config,
    )
    .expect("same-shard chain must verify");
    consensus_verify_chain(
        &[blk0.clone(), blk1_ok.clone()],
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config.consensus(),
        false,
        false,
        false,
    )
    .expect("consensus::verify_chain must accept same-shard chain");

    // Mid-chain shard_id mismatch must be rejected by both verify_chain entry points.
    let err_lib = verify_chain(
        &[blk0.clone(), blk1_bad_shard.clone()],
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config,
    )
    .expect_err("lib::verify_chain must reject shard_id mismatch");
    assert!(err_lib.to_string().contains("shard_id"));

    let err_cons = consensus_verify_chain(
        &[blk0.clone(), blk1_bad_shard.clone()],
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config.consensus(),
        false,
        false,
        false,
    )
    .expect_err("consensus::verify_chain must reject shard_id mismatch");
    assert!(err_cons.contains("shard_id"));

    // verify_proposer_signature_with_config honors custom header_commit_activation_height.
    let mut v3_cfg = config.consensus();
    v3_cfg.header_commit_activation_height = u64::MAX;
    let mut blk_v3 = WireBlock {
        shard_id: 0,
        height: 1,
        timestamp: 1_700_000_001,
        proposer: val_id,
        ..WireBlock::default()
    };
    sign_block(&mut blk_v3, u64::MAX);
    assert!(verify_proposer_signature_with_config(
        &blk_v3, &keys, v3_cfg
    ));
    assert!(!verify_proposer_signature_with_config(
        &blk_v3,
        &keys,
        config.consensus()
    ));

    // CLI verify-chain also rejects shard_id mismatch and honors --schedule / activation flags.
    let dir = TempDir::new("chain-shard");
    let b0_path = dir.write_bytes(
        "b0.bin",
        &encode_block_v7_canonical(&blk0).expect("encode b0"),
    );
    let b1_ok_path = dir.write_bytes(
        "b1_ok.bin",
        &encode_block_v7_canonical(&blk1_ok).expect("encode b1_ok"),
    );
    let b1_bad_path = dir.write_bytes(
        "b1_bad.bin",
        &encode_block_v7_canonical(&blk1_bad_shard).expect("encode b1_bad"),
    );
    let val_path = dir.write(
        "validators.txt",
        &format!(
            "0x{} 1000000 0X02 0X{}\n",
            to_hex(&val_id),
            to_hex(kp.public_key())
        ),
    );

    let out_bad_cli = run(&[
        "verify-chain",
        b0_path.to_str().expect("utf-8 path"),
        b1_bad_path.to_str().expect("utf-8 path"),
        "--validators",
        val_path.to_str().expect("utf-8 path"),
        "--schedule",
        "parent-hash",
        "--qc-split-height",
        "100",
        "--sortition-unbiased-height",
        "100",
        "--header-commit-height",
        "0",
    ]);
    assert_eq!(out_bad_cli.status.code(), Some(1));

    let out_ok_cli = run(&[
        "verify-chain",
        b0_path.to_str().expect("utf-8 path"),
        b1_ok_path.to_str().expect("utf-8 path"),
        "--validators",
        val_path.to_str().expect("utf-8 path"),
        "--schedule",
        "parent-hash",
        "--qc-split-height",
        "100",
        "--sortition-unbiased-height",
        "100",
        "--header-commit-height",
        "0",
    ]);
    assert_eq!(
        out_ok_cli.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out_ok_cli.stderr)
    );
}
