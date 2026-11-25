//! Wave 8 CLI unjail fee-floor retry, SendPq seed-file/env resolution,
//! and stellereum-upgrader security closure tests.

#[allow(dead_code)]
#[path = "../src/cli/args.rs"]
mod args;

#[allow(dead_code)]
#[path = "../src/cli/tx_builders.rs"]
mod tx_builders;

#[allow(dead_code)]
#[path = "../../stellereum-upgrader/src/lib.rs"]
mod upgrader;

use clap::Parser;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_dir(tag: &str) -> PathBuf {
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("stell-w8-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
    dir
}

#[test]
fn build_unjail_tx_with_chain_and_gas_respects_gas_override() {
    let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x41);
    let validator = [0x22u8; 32];
    let cid = stellereum::consensus::consensus_chain_id();
    let default_gas = tx_builders::unjail_default_gas(None);

    let tx_default =
        tx_builders::build_unjail_tx_with_chain_and_gas(&kp, validator, None, 10, cid, None);
    assert_eq!(tx_default.gas_limit, default_gas);
    assert!(tx_default.verify_signature_for_chain(cid, true));

    let tx_below =
        tx_builders::build_unjail_tx_with_chain_and_gas(&kp, validator, None, 10, cid, Some(1));
    assert_eq!(
        tx_below.gas_limit, default_gas,
        "gas_override below default_gas must floor at default_gas"
    );
    assert!(tx_below.verify_signature_for_chain(cid, true));

    let tx_escalated = tx_builders::build_unjail_tx_with_chain_and_gas(
        &kp,
        validator,
        None,
        10,
        cid,
        Some(1_300_000),
    );
    assert_eq!(tx_escalated.gas_limit, 1_300_000);
    assert_eq!(tx_escalated.nonce, 10);
    assert!(tx_escalated.verify_signature_for_chain(cid, true));

    let tx_topup_escalated = tx_builders::build_unjail_tx_with_chain_and_gas(
        &kp,
        validator,
        Some(5_000_000_000),
        11,
        cid,
        Some(2_600_000),
    );
    assert_eq!(tx_topup_escalated.gas_limit, 2_600_000);
    assert_eq!(tx_topup_escalated.payload.len(), 2);
    assert!(tx_topup_escalated.verify_signature_for_chain(cid, true));

    let tx_unbound = tx_builders::build_unjail_tx_with_gas(&kp, validator, None, 12, Some(650_000));
    assert_eq!(tx_unbound.gas_limit, 650_000);
    assert!(tx_unbound.verify_signature());
}

#[test]
fn wallet_send_pq_parses_falcon_seed_file_without_falcon_seed() {
    let to_hex = "ab".repeat(32);
    let cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "send-pq",
        "--falcon-seed-file",
        "/tmp/faucet.seed",
        "--to",
        &to_hex,
        "--amount",
        "42000",
        "--target-shard",
        "1",
    ])
    .expect("wallet send-pq should parse --falcon-seed-file without --falcon-seed");

    match cli.command {
        args::Commands::Wallet {
            sub:
                args::WalletCommands::SendPq {
                    falcon_seed,
                    falcon_seed_file,
                    amount,
                    target_shard,
                    ..
                },
        } => {
            assert_eq!(falcon_seed, None);
            assert_eq!(falcon_seed_file, Some(PathBuf::from("/tmp/faucet.seed")));
            assert_eq!(amount, 42_000);
            assert_eq!(target_shard, 1);
        }
        _ => panic!("expected WalletCommands::SendPq"),
    }

    let env_cli = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "send-pq",
        "--to",
        &to_hex,
        "--amount",
        "1",
    ])
    .expect("wallet send-pq should allow omitting seed flags for STELL_FALCON_SEED env fallback");
    assert!(matches!(
        env_cli.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::SendPq {
                falcon_seed: None,
                falcon_seed_file: None,
                ..
            }
        }
    ));

    let val_unjail = args::Cli::try_parse_from([
        "stellereum",
        "validator",
        "unjail",
        "--withdrawal-key-file",
        "/tmp/cold.key",
        "--validator-id",
        &to_hex,
        "--gas-limit",
        "900000",
    ])
    .expect("validator unjail should parse --gas-limit");
    assert!(matches!(
        val_unjail.command,
        args::Commands::Validator {
            sub: args::ValidatorCommands::Unjail {
                gas_limit: Some(900_000),
                ..
            }
        }
    ));

    let wal_unjail = args::Cli::try_parse_from([
        "stellereum",
        "wallet",
        "unjail",
        "--falcon-key-file",
        "/tmp/cold.key",
        "--gas-limit",
        "650000",
    ])
    .expect("wallet unjail should parse --gas-limit");
    assert!(matches!(
        wal_unjail.command,
        args::Commands::Wallet {
            sub: args::WalletCommands::Unjail {
                gas_limit: Some(650_000),
                ..
            }
        }
    ));
}

#[test]
fn resolve_falcon_seed_reads_file_and_env_fallback() {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_LOCK.lock().expect("env lock");
    let prev = std::env::var_os("STELL_FALCON_SEED");
    std::env::remove_var("STELL_FALCON_SEED");

    let dir = temp_dir("seed");
    let seed_path = dir.join("faucet.seed");
    let hex_seed = "3c".repeat(32);
    std::fs::write(&seed_path, format!("0x{hex_seed}\n")).expect("write seed");

    let from_file =
        tx_builders::resolve_falcon_seed(None, Some(seed_path)).expect("resolve from file");
    assert_eq!(*from_file, [0x3cu8; 32]);

    std::env::set_var("STELL_FALCON_SEED", &hex_seed);
    let from_env = tx_builders::resolve_falcon_seed(None, None).expect("resolve from env");
    assert_eq!(*from_env, [0x3cu8; 32]);

    std::env::remove_var("STELL_FALCON_SEED");
    assert!(tx_builders::resolve_falcon_seed(None, None).is_err());

    if let Some(v) = prev {
        std::env::set_var("STELL_FALCON_SEED", v);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn upgrade_plan_read_rpc_refuses_http_3xx_redirects() {
    for status in [
        "302 Found",
        "301 Moved Permanently",
        "307 Temporary Redirect",
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let reply = format!(
                    "HTTP/1.1 {status}\r\nLocation: http://127.0.0.1:9/evil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
            }
        });
        let url = format!("http://{addr}");
        let err = upgrader::UpgradePlan::read_rpc(&url)
            .expect_err("UpgradePlan::read_rpc must refuse HTTP 3xx redirects");
        let code = &status[..3];
        assert!(err.contains(code), "expected HTTP {code} error, got: {err}");
        let _ = handle.join();
    }
}

#[test]
fn upgrader_progress_rejects_writable_parents_and_symlink_target() {
    let dir = temp_dir("progress");

    let group_dir = dir.join("group");
    std::fs::create_dir_all(&group_dir).expect("mkdir group");
    std::fs::set_permissions(&group_dir, std::fs::Permissions::from_mode(0o775)).expect("chmod");
    let err = upgrader::Progress::new(group_dir.join("progress.log"))
        .record("start", "test")
        .expect_err("0o020 group-writable parent must be rejected");
    assert!(err.contains("GROUP-WRITABLE"), "{err}");

    let world_dir = dir.join("world");
    std::fs::create_dir_all(&world_dir).expect("mkdir world");
    std::fs::set_permissions(&world_dir, std::fs::Permissions::from_mode(0o757)).expect("chmod");
    let err = upgrader::Progress::new(world_dir.join("progress.log"))
        .record("start", "test")
        .expect_err("0o002 world-writable parent must be rejected");
    assert!(err.contains("WORLD-WRITABLE"), "{err}");

    let safe_dir = dir.join("safe");
    std::fs::create_dir_all(&safe_dir).expect("mkdir safe");
    std::fs::set_permissions(&safe_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let real_target = safe_dir.join("real.log");
    std::fs::write(&real_target, b"").expect("write real");
    let symlink_target = safe_dir.join("sym.log");
    std::os::unix::fs::symlink(&real_target, &symlink_target).expect("symlink");
    let err = upgrader::Progress::new(symlink_target)
        .record("start", "test")
        .expect_err("symlink progress target must be rejected");
    assert!(err.contains("SYMLINK"), "{err}");

    let ok_progress = upgrader::Progress::new(safe_dir.join("ok.log"));
    ok_progress
        .record("start", "ok")
        .expect("0o755 parent with regular file must succeed");

    let _ = std::fs::remove_dir_all(&dir);
}
