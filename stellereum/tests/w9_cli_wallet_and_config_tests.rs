//! Wave 9 CLI wallet consistency, remote-signer serve, contract deploy/call,
//! STELL_DATA_DIR wiring, round_timeout_ms warning, and flock fail-fast tests.

#[allow(dead_code)]
#[path = "../src/cli/args.rs"]
mod args;

#[allow(dead_code)]
#[path = "../src/cli/tx_builders.rs"]
mod tx_builders;

#[allow(dead_code)]
#[path = "../src/node/policy.rs"]
mod policy;

use clap::Parser;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use stellereum::node_config::NodeTomlConfig;
use stellereum::post_quantum::FalconKeypair;
use zeroize::Zeroizing;

static ENV_LOCK: Mutex<()> = Mutex::new(());
static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_dir(tag: &str) -> PathBuf {
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("stell-w9-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn wallet_generate_and_address_derive_spendable_falcon_pq_address() {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    let seed_hex = Zeroizing::new(hex::encode(*seed));

    // Wallet generation path: FalconKeypair::generate_from_seed_bytes + falcon_pq_address.
    let gen_kp = FalconKeypair::generate_from_seed_bytes(&seed);
    let gen_addr = tx_builders::falcon_pq_address(&gen_kp);

    // Wallet address / wallet send path: falcon_from_hex_seed + falcon_pq_address.
    let addr_kp = tx_builders::falcon_from_hex_seed(&seed_hex, "from_key").expect("decode seed");
    let addr_derived = tx_builders::falcon_pq_address(&addr_kp);
    assert_eq!(gen_addr, addr_derived);

    // Sign a transfer transaction spending from that address and verify chain-bound PQ1 sig.
    let to = [0x55u8; 32];
    let cid = stellereum::consensus::consensus_chain_id();
    let gas =
        stellereum::svm::GAS_BASIC_TRANSFER + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    let tx = tx_builders::sign_pq_explicit_transfer_with_chain(
        &addr_kp,
        to,
        1_000_000_000,
        gas,
        0,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        cid,
    );
    assert_eq!(tx.from, gen_addr);
    assert!(tx.verify_signature());
    assert!(tx.verify_signature_for_chain(cid, true));
}

#[test]
fn cli_parses_wallet_consistency_and_falcon_seed_file_flags() {
    let addr_hex = "11".repeat(32);
    let to_hex = "22".repeat(32);

    // wallet balance --address ... --rpc ...
    let bal_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "balance",
        "--address",
        &addr_hex,
        "--rpc",
        "http://127.0.0.1:9545",
    ])
    .expect("parse wallet balance with --rpc");
    match bal_cli.command {
        args::Commands::Wallet {
            sub: args::WalletCommands::Balance { address, rpc },
        } => {
            assert_eq!(address, addr_hex);
            assert_eq!(rpc, "http://127.0.0.1:9545");
        }
        _ => panic!("expected WalletCommands::Balance"),
    }

    // wallet address --falcon-seed-file ...
    let addr_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "address",
        "--falcon-seed-file",
        "/tmp/wallet.seed",
    ])
    .expect("parse wallet address --falcon-seed-file");
    assert!(matches!(
        addr_cli.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::Address {
                from_key: None,
                falcon_seed: None,
                falcon_seed_file: Some(_),
                falcon_key_file: None,
            }
        }
    ));

    // wallet send with optional --from-key and --falcon-seed-file
    let send_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "send",
        "--falcon-seed-file",
        "/tmp/wallet.seed",
        "--to",
        &to_hex,
        "--amount",
        "5000",
    ])
    .expect("parse wallet send --falcon-seed-file");
    assert!(matches!(
        send_cli.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::Send {
                from_key: None,
                falcon_seed: None,
                falcon_seed_file: Some(_),
                amount: 5000,
                ..
            }
        }
    ));

    // wallet sign --falcon-seed-file
    let sign_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "sign",
        "--falcon-seed-file",
        "/tmp/wallet.seed",
        "--message",
        "hello",
    ])
    .expect("parse wallet sign --falcon-seed-file");
    assert!(matches!(
        sign_cli.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::Sign {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    // wallet sign-typed-data --falcon-seed-file
    let typed_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "sign-typed-data",
        "--falcon-seed-file",
        "/tmp/wallet.seed",
        "--contract",
        &addr_hex,
        "--method",
        "transfer",
    ])
    .expect("parse wallet sign-typed-data --falcon-seed-file");
    assert!(matches!(
        typed_cli.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::SignTypedData {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    // wallet unjail --falcon-seed-file
    let unjail_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "unjail",
        "--falcon-seed-file",
        "/tmp/wallet.seed",
    ])
    .expect("parse wallet unjail --falcon-seed-file");
    assert!(matches!(
        unjail_cli.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::Unjail {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    // gov propose / vote --falcon-seed-file
    let gov_prop = args::Cli::try_parse_from([
        "stellereum",
        "gov",
        "propose",
        "--falcon-seed-file",
        "/tmp/gov.seed",
        "--title",
        "Signal",
        "--action",
        "signal",
    ])
    .expect("parse gov propose --falcon-seed-file");
    assert!(matches!(
        gov_prop.command,
        args::Commands::Gov {
            sub: args::GovCommands::Propose {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    let gov_vote = args::Cli::try_parse_from([
        "stellereum",
        "gov",
        "vote",
        "--falcon-seed-file",
        "/tmp/gov.seed",
        "--id",
        "1",
        "--choice",
        "yes",
    ])
    .expect("parse gov vote --falcon-seed-file");
    assert!(matches!(
        gov_vote.command,
        args::Commands::Gov {
            sub: args::GovCommands::Vote {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    // validator delegate / begin-undelegate / withdraw-delegation --falcon-seed-file
    let del_cli = args::Cli::try_parse_from([
        "stellereum",
        "validator",
        "delegate",
        "--falcon-seed-file",
        "/tmp/del.seed",
        "--validator-id",
        &addr_hex,
        "--amount",
        "1000",
    ])
    .expect("parse validator delegate --falcon-seed-file");
    assert!(matches!(
        del_cli.command,
        args::Commands::Validator {
            sub: args::ValidatorCommands::Delegate {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    let undel_cli = args::Cli::try_parse_from([
        "stellereum",
        "validator",
        "begin-undelegate",
        "--falcon-seed-file",
        "/tmp/del.seed",
        "--validator-id",
        &addr_hex,
        "--amount",
        "500",
    ])
    .expect("parse validator begin-undelegate --falcon-seed-file");
    assert!(matches!(
        undel_cli.command,
        args::Commands::Validator {
            sub: args::ValidatorCommands::BeginUndelegate {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));

    let wdel_cli = args::Cli::try_parse_from([
        "stellereum",
        "validator",
        "withdraw-delegation",
        "--falcon-seed-file",
        "/tmp/del.seed",
        "--validator-id",
        &addr_hex,
    ])
    .expect("parse validator withdraw-delegation --falcon-seed-file");
    assert!(matches!(
        wdel_cli.command,
        args::Commands::Validator {
            sub: args::ValidatorCommands::WithdrawDelegation {
                falcon_seed_file: Some(_),
                ..
            }
        }
    ));
}

#[test]
fn cli_parses_remote_signer_serve_and_enforces_fail_closed_policy() {
    let default_cli = args::Cli::try_parse_from(["stellereum", "remote-signer", "serve"])
        .expect("parse remote-signer serve defaults");
    match default_cli.command {
        args::Commands::RemoteSigner {
            sub:
                args::RemoteSignerCommands::Serve {
                    listen,
                    falcon_key_file,
                    data_dir,
                    token,
                    token_file,
                    allow_insecure_http,
                    genesis_hash,
                    shard,
                },
        } => {
            assert_eq!(listen, "127.0.0.1:8443");
            assert_eq!(falcon_key_file, None);
            assert_eq!(data_dir, PathBuf::from("./remote-signer-data"));
            assert_eq!(token, None);
            assert_eq!(token_file, None);
            assert!(!allow_insecure_http);
            assert_eq!(genesis_hash, None);
            assert_eq!(shard, 0);
        }
        _ => panic!("expected Commands::RemoteSigner"),
    }

    let custom_cli = args::Cli::try_parse_from([
        "stellereum",
        "remote-signer",
        "serve",
        "--listen",
        "0.0.0.0:9443",
        "--falcon-key-file",
        "/etc/stellereum/falcon.key",
        "--data-dir",
        "/var/lib/stellereum-signer",
        "--token-file",
        "/etc/stellereum/signer.token",
        "--allow-insecure-http",
    ])
    .expect("parse remote-signer serve flags");
    assert!(matches!(
        custom_cli.command,
        args::Commands::RemoteSigner {
            sub: args::RemoteSignerCommands::Serve {
                allow_insecure_http: true,
                token_file: Some(_),
                ..
            }
        }
    ));

    let _guard = ENV_LOCK.lock().expect("env lock");
    let prev_tok = std::env::var_os(stellereum::remote_signer::REMOTE_SIGNER_TOKEN_ENV);
    std::env::remove_var(stellereum::remote_signer::REMOTE_SIGNER_TOKEN_ENV);

    // Non-loopback without --allow-insecure-http must fail closed.
    assert!(tx_builders::validate_remote_signer_serve_policy(
        "0.0.0.0:8443",
        Some("secret-tok".to_string()),
        None,
        false,
    )
    .is_err());

    // Loopback without any bearer token must fail closed.
    assert!(
        tx_builders::validate_remote_signer_serve_policy("127.0.0.1:8443", None, None, false,)
            .is_err()
    );

    // Loopback with token succeeds.
    let tok = tx_builders::validate_remote_signer_serve_policy(
        "127.0.0.1:8443",
        Some("secret-tok".to_string()),
        None,
        false,
    )
    .expect("loopback with token must succeed");
    assert_eq!(&*tok, "secret-tok");

    // Token file succeeds and trims whitespace.
    let dir = temp_dir("signer-tok");
    let tok_path = dir.join("bearer.tok");
    std::fs::write(&tok_path, "  file-secret-tok \n").expect("write token file");
    let tok_from_file = tx_builders::validate_remote_signer_serve_policy(
        "0.0.0.0:8443",
        None,
        Some(tok_path),
        true,
    )
    .expect("explicit --allow-insecure-http with token file");
    assert_eq!(&*tok_from_file, "file-secret-tok");
    let _ = std::fs::remove_dir_all(&dir);

    if let Some(v) = prev_tok {
        std::env::set_var(stellereum::remote_signer::REMOTE_SIGNER_TOKEN_ENV, v);
    }
}

#[test]
fn cli_parses_contract_deploy_and_call_and_builds_verified_txs() {
    let contract_hex = "cc".repeat(32);
    let deploy_cli = args::Cli::try_parse_from([
        "stellereum",
        "contract",
        "deploy",
        "--wasm-file",
        "/tmp/counter.wasm",
        "--falcon-seed-file",
        "/tmp/dev.seed",
        "--nonce",
        "3",
        "--chain-id",
        "5757",
        "--dry-run",
    ])
    .expect("parse contract deploy");
    assert!(matches!(
        deploy_cli.command,
        args::Commands::Contract {
            sub: args::ContractCommands::Deploy {
                falcon_seed_file: Some(_),
                nonce: Some(3),
                chain_id: Some(5757),
                dry_run: true,
                ..
            }
        }
    ));

    let call_cli = args::Cli::try_parse_from([
        "stellereum",
        "contract",
        "call",
        "--contract",
        &contract_hex,
        "--method",
        "increment",
        "--args",
        "[1, 2]",
        "--falcon-seed",
        &"44".repeat(32),
        "--value",
        "100",
        "--dry-run",
    ])
    .expect("parse contract call");
    assert!(matches!(
        call_cli.command,
        args::Commands::Contract {
            sub: args::ContractCommands::Call {
                value: 100,
                dry_run: true,
                ..
            }
        }
    ));

    let kp = FalconKeypair::generate_from_seed(0x63);
    let cid = stellereum::consensus::consensus_chain_id();
    let wasm = b"\0asm\x01\0\0\0".to_vec();
    let deploy_tx =
        tx_builders::build_contract_deploy_tx(&kp, wasm.clone(), 4, None, Some(cid)).unwrap();
    assert!(deploy_tx.verify_signature_for_chain(cid, true));
    let expected_min_gas =
        tx_builders::cli_tx_gas(stellereum::svm::contract_deploy_gas(wasm.len()))
            + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    assert_eq!(deploy_tx.gas_limit, expected_min_gas);
    assert!(matches!(
        &deploy_tx.payload[0],
        stellereum::svm::OpCode::SysCallDeployContract { code } if code == &wasm
    ));

    let contract_addr = [0xccu8; 32];
    let op_single = tx_builders::parse_contract_call_opcode(contract_addr, "set", Some("42"))
        .expect("single i64 arg");
    assert!(matches!(
        op_single,
        stellereum::svm::OpCode::SysCallCallContract { arg: 42, .. }
    ));

    let op_multi = tx_builders::parse_contract_call_opcode(
        contract_addr,
        "transfer",
        Some(&format!("[10, \"0x{}\"]", "aa".repeat(32))),
    )
    .expect("multi abi args");
    match &op_multi {
        stellereum::svm::OpCode::SysCallCallContractArgs { args, calldata, .. } => {
            assert_eq!(args, &[10, 0]);
            assert!(!calldata.is_empty());
        }
        other => panic!("expected SysCallCallContractArgs, got {other:?}"),
    }
    let call_tx = tx_builders::build_contract_call_tx(
        &kp,
        contract_addr,
        op_multi,
        250,
        5,
        Some(500_000),
        Some(cid),
    );
    assert_eq!(call_tx.to, contract_addr);
    assert_eq!(call_tx.amount, 250);

    // --calldata supports raw hex payloads for *_pq entrypoints and rejects --args conflict.
    let raw_cd_hex = format!("0x2a00000000000000{}", "bb".repeat(32));
    let raw_cli = args::Cli::try_parse_from([
        "stellereum",
        "contract",
        "call",
        "--contract",
        &contract_hex,
        "--method",
        "set_target_pq",
        "--calldata",
        &raw_cd_hex,
        "--dry-run",
    ])
    .expect("parse contract call --calldata");
    assert!(matches!(
        raw_cli.command,
        args::Commands::Contract {
            sub: args::ContractCommands::Call {
                calldata: Some(_),
                args: None,
                dry_run: true,
                ..
            }
        }
    ));
    assert!(args::Cli::try_parse_from([
        "stellereum",
        "contract",
        "call",
        "--contract",
        &contract_hex,
        "--method",
        "set_target_pq",
        "--args",
        "[1]",
        "--calldata",
        "0x0102",
    ])
    .is_err());

    let op_raw = tx_builders::parse_contract_call_opcode_with_calldata(
        contract_addr,
        "set_target_pq",
        None,
        Some(&raw_cd_hex),
    )
    .expect("raw calldata opcode");
    match &op_raw {
        stellereum::svm::OpCode::SysCallCallContractArgs {
            method,
            args,
            calldata,
            ..
        } => {
            assert_eq!(method, b"set_target_pq");
            assert!(args.is_empty());
            assert_eq!(calldata.len(), 40);
            assert_eq!(&calldata[..8], &42u64.to_le_bytes());
            assert_eq!(&calldata[8..], &[0xbb; 32]);
        }
        other => panic!("expected SysCallCallContractArgs, got {other:?}"),
    }
    let raw_tx =
        tx_builders::build_contract_call_tx(&kp, contract_addr, op_raw, 0, 6, None, Some(cid));
    assert!(raw_tx.verify_signature_for_chain(cid, true));
    assert_eq!(call_tx.gas_limit, 500_000);
    assert!(call_tx.verify_signature_for_chain(cid, true));
}

#[test]
fn store_and_mempool_paths_respect_stell_data_dir() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let prev = std::env::var_os("STELL_DATA_DIR");

    std::env::remove_var("STELL_DATA_DIR");
    assert_eq!(
        policy::data_dir_from_env(),
        PathBuf::from("./data"),
        "default data dir must remain ./data"
    );
    assert_eq!(
        policy::store_path_for_shard(0, false),
        PathBuf::from("./data/store")
    );
    assert_eq!(
        policy::mempool_path_for_shard(0, false),
        PathBuf::from("./data/mempool.bin")
    );

    std::env::set_var("STELL_DATA_DIR", "/var/lib/stellereum-custom");
    assert_eq!(
        policy::data_dir_from_env(),
        PathBuf::from("/var/lib/stellereum-custom")
    );
    assert_eq!(
        policy::store_path_for_shard(0, false),
        PathBuf::from("/var/lib/stellereum-custom/store")
    );
    assert_eq!(
        policy::store_path_for_shard(1, true),
        PathBuf::from("/var/lib/stellereum-custom/store-shard1")
    );
    assert_eq!(
        policy::mempool_path_for_shard(0, false),
        PathBuf::from("/var/lib/stellereum-custom/mempool.bin")
    );
    assert_eq!(
        policy::mempool_path_for_shard(1, true),
        PathBuf::from("/var/lib/stellereum-custom/mempool-shard1.bin")
    );

    match prev {
        Some(v) => std::env::set_var("STELL_DATA_DIR", v),
        None => std::env::remove_var("STELL_DATA_DIR"),
    }
}

#[test]
fn acquire_node_dir_lock_rejects_concurrent_lock_and_releases_on_drop() {
    let dir = temp_dir("flock");
    let first = policy::acquire_node_dir_lock(&dir).expect("first lock acquisition succeeds");
    assert!(dir.join(".node.lock").exists());

    let err = policy::acquire_node_dir_lock(&dir)
        .expect_err("second concurrent lock on same data dir must fail loudly");
    let msg = err.to_string();
    assert!(
        msg.contains(".node.lock") && msg.contains("exclusive lock"),
        "unexpected lock error message: {msg}"
    );

    drop(first);
    let reacquired = policy::acquire_node_dir_lock(&dir).expect("lock must be released after drop");
    drop(reacquired);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn node_config_round_timeout_warning_and_toml_example_valid() {
    let example = include_str!("../stellereum.toml.example");
    let cfg = NodeTomlConfig::from_toml_str(example).expect("stellereum.toml.example must parse");
    assert_eq!(cfg.tempo.min_block_ms, Some(400));
    assert_eq!(cfg.storage.archive, Some(false));
    assert_eq!(cfg.storage.keep_blocks, Some(50_000));
    assert_eq!(cfg.consensus.shards.as_deref(), Some("0"));
    assert_eq!(cfg.tempo.round_timeout_ms, None);

    let rep = cfg.validate_with_env(|_| None);
    assert!(rep.is_ok(), "example config errors: {:?}", rep.errors);
    assert!(
        rep.warnings.is_empty(),
        "example config warnings: {:?}",
        rep.warnings
    );

    let deprecated_toml = NodeTomlConfig::from_toml_str("[tempo]\nround_timeout_ms = 3000\n")
        .expect("backwards-compat round_timeout_ms parses");
    let warn_rep = deprecated_toml.validate_with_env(|_| None);
    assert!(warn_rep.is_ok());
    assert!(warn_rep
        .warnings
        .iter()
        .any(|w| w.contains("FROZEN_ROUND_TIMEOUT_BASE_MS")));

    let mut env = HashMap::new();
    env.insert("STELL_ROUND_TIMEOUT_MS", "3500".to_string());
    let env_rep = NodeTomlConfig::default().validate_with_env(|k| env.get(k).cloned());
    assert!(env_rep
        .warnings
        .iter()
        .any(|w| w.contains("FROZEN_ROUND_TIMEOUT_BASE_MS")));
}
