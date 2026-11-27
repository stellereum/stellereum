//! Offline verification CLI.
//!
//! Uses only `std` for argument parsing, file IO, and process exit. Every
//! verification input (chain id, validator file, activation heights) is
//! explicit; the process never reads an environment variable or contacts a
//! node.
//!
//! ```text
//! stellereum-verifier verify-tx       <tx.bin>       [--chain-id N] [--require-chain-id]
//! stellereum-verifier verify-block    <block.bin>    [--chain-id N] [--validators FILE]
//!                                                    [--schedule parent-hash|beacon]
//!                                                    [--qc-split-height H]
//!                                                    [--sortition-unbiased-height H]
//!                                                    [--header-commit-height H]
//!                                                    [--require-qc] [--require-chain-id] [--verify-txs]
//! stellereum-verifier verify-chain    <block.bin>... [same options as verify-block]
//! stellereum-verifier verify-snapshot [--state-root <hex32>] [--block <block.bin>]
//!                                     --snapshot <json-file> (--proof <json-file> | --accounts <json-file>)
//! stellereum-verifier verify-proof    --state-root <hex32> --key <hex32> (--value <hex> | --absent) --proof <json-file>
//! ```
//!
//! A validator file has one record per line:
//!
//! ```text
//! # <hex validator id> <power> [<scheme id> <hex PQ pubkey>]
//! 001122...  1000000  02 09abcdef...
//! ```
//!
//! The optional scheme/pubkey pair enables proposer and QC signature checks.
//! Without a validator file, `verify-block` / `verify-chain` perform the
//! structural checks that need no key material: strict canonical v7 decoding,
//! order Merkle root, cross-shard message ids, and parent-hash linkage.

use std::env;
use std::fs;
use std::process;

use stellereum_verifier::block_hash;
use stellereum_verifier::commitment::{self as vc, MerkleProof, VerifierCommitmentSnapshot};
use stellereum_verifier::consensus::{CommitteeSchedule, StaticPqKeyRegistry, ValidatorSet};
use stellereum_verifier::tx::{self as txmod, ImplicitKeyRegistry};
use stellereum_verifier::wire::{self, PqScheme};
use stellereum_verifier::{
    verify_block, verify_chain, verify_commitment_exclusion, verify_state_root_against_snapshot,
    verify_state_root_full, verify_tx, VerifierConfig, VerifyError,
};

const USAGE: &str = "\
stellereum-verifier — offline Stellereum L1 verifier

USAGE:
    stellereum-verifier verify-tx       <tx.bin>       [OPTIONS]
    stellereum-verifier verify-block    <block.bin>    [OPTIONS]
    stellereum-verifier verify-chain    <block.bin>... [OPTIONS]
    stellereum-verifier verify-snapshot [--state-root <hex32>] [--block <block.bin>]
                                        --snapshot <json> (--proof <json> | --accounts <json>)
    stellereum-verifier verify-proof    --state-root <hex32> --key <hex32>
                                        (--value <hex> | --absent) --proof <json>

OPTIONS (block / chain):
    --chain-id <N>                    Chain id to bind (default 5757)
    --validators <FILE>               Validator set / PQ key history for block & chain checks
    --schedule <parent-hash|beacon>   Committee sortition schedule (default parent-hash)
    --qc-split-height <H>             C1 uQC/full-QC split activation height
    --sortition-unbiased-height <H>   Unbiased rejection-sampling sortition activation height
    --header-commit-height <H>        v4 header commitment activation height
    --require-qc                      Refuse a block without a precommit QC
    --require-chain-id                Refuse transactions that do not bind chain_id
    --verify-txs                      Verify every transaction inside a block / chain
    -h, --help                        Print this help

SNAPSHOT / PROOF OPTIONS & JSON:
    --state-root <hex32>  32-byte state root (accepts optional 0x/0X prefix).
                          For verify-snapshot, optional when --block is given;
                          when both are given, they must match.
    --block <FILE>        Canonical v7 block whose header state_root is bound.
    --snapshot <FILE>     Object with \"version\" (number) and the domain blobs
                          as hex strings: tokens, staking, pmm, contracts, escrow,
                          governance, oracle, session_keys, books, bridge,
                          cross_shard, xpc, and optional zkml, cnvrf,
                          total_minted_nano (u64), evm_bindings, pq_registry.
    --proof <FILE>        JSON array of canonical proof nodes, exactly as
                          `stellereum::cpat2::MerkleProof::to_nodes()` emits them
                          (one hex string per node, leaf first).
    --accounts <FILE>     JSON array of {\"key\":\"<hex32>\",\"value\":\"<hex>\"}
                          covering every trie leaf except the commitment leaf.
    --absent              Verify an exclusion proof (key is absent at state-root).

Exit codes: 0 = verified, 1 = cryptographic/consensus/wire verification failure,
2 = usage, IO, or JSON/hex parse error.";

type CliResult = Result<(), (i32, String)>;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{USAGE}");
        return;
    }

    let command = args[0].clone();
    let rest = &args[1..];
    let result = match command.as_str() {
        "verify-tx" => run_verify_tx(rest),
        "verify-block" => run_verify_block(rest),
        "verify-chain" => run_verify_chain(rest),
        "verify-snapshot" => run_verify_snapshot(rest),
        "verify-proof" => run_verify_proof(rest),
        "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err((2, format!("unknown command `{other}`\n\n{USAGE}"))),
    };

    if let Err((code, message)) = result {
        if !message.is_empty() {
            eprintln!("{message}");
        }
        process::exit(code);
    }
}

#[derive(Default)]
struct Options {
    chain_id: Option<u64>,
    validators: Option<String>,
    schedule: Option<CommitteeSchedule>,
    qc_split_height: Option<u64>,
    sortition_unbiased_height: Option<u64>,
    header_commit_height: Option<u64>,
    require_qc: bool,
    require_chain_id: bool,
    verify_txs: bool,
    files: Vec<String>,
}

fn parse_options(args: &[String]) -> Result<Options, (i32, String)> {
    let mut options = Options::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--chain-id" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| (2, "--chain-id needs a value".to_string()))?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| (2, format!("invalid chain id `{value}`")))?;
                options.chain_id = Some(parsed);
                i += 2;
            }
            "--validators" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| (2, "--validators needs a path".to_string()))?;
                options.validators = Some(value.clone());
                i += 2;
            }
            "--schedule" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| (2, "--schedule needs `parent-hash` or `beacon`".to_string()))?;
                let schedule = match value.as_str() {
                    "parent-hash" => CommitteeSchedule::ParentHash,
                    "beacon" => CommitteeSchedule::Beacon(None),
                    other => {
                        return Err((
                            2,
                            format!(
                                "invalid --schedule `{other}` (expected `parent-hash` or `beacon`)"
                            ),
                        ))
                    }
                };
                options.schedule = Some(schedule);
                i += 2;
            }
            "--qc-split-height" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| (2, "--qc-split-height needs a value".to_string()))?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| (2, format!("invalid --qc-split-height `{value}`")))?;
                options.qc_split_height = Some(parsed);
                i += 2;
            }
            "--sortition-unbiased-height" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| (2, "--sortition-unbiased-height needs a value".to_string()))?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| (2, format!("invalid --sortition-unbiased-height `{value}`")))?;
                options.sortition_unbiased_height = Some(parsed);
                i += 2;
            }
            "--header-commit-height" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| (2, "--header-commit-height needs a value".to_string()))?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| (2, format!("invalid --header-commit-height `{value}`")))?;
                options.header_commit_height = Some(parsed);
                i += 2;
            }
            "--require-qc" => {
                options.require_qc = true;
                i += 1;
            }
            "--require-chain-id" => {
                options.require_chain_id = true;
                i += 1;
            }
            "--verify-txs" => {
                options.verify_txs = true;
                i += 1;
            }
            "-h" | "--help" => return Err((0, USAGE.to_string())),
            flag if flag.starts_with('-') => {
                return Err((2, format!("unknown option `{flag}`\n\n{USAGE}")))
            }
            file => {
                options.files.push(file.to_string());
                i += 1;
            }
        }
    }
    Ok(options)
}

fn chain_id(options: &Options) -> u64 {
    options.chain_id.unwrap_or(wire::DEFAULT_CHAIN_ID)
}

fn verifier_config(options: &Options) -> VerifierConfig {
    let defaults = VerifierConfig::default();
    VerifierConfig {
        chain_id: options.chain_id.unwrap_or(defaults.chain_id),
        qc_split_activation_height: options
            .qc_split_height
            .unwrap_or(defaults.qc_split_activation_height),
        sortition_unbiased_activation_height: options
            .sortition_unbiased_height
            .unwrap_or(defaults.sortition_unbiased_activation_height),
        header_commit_activation_height: options
            .header_commit_height
            .unwrap_or(defaults.header_commit_activation_height),
        require_qc: options.require_qc,
        verify_txs: options.verify_txs,
        require_tx_chain_id: options.require_chain_id,
    }
}

fn committee_schedule(options: &Options) -> CommitteeSchedule {
    options.schedule.unwrap_or(CommitteeSchedule::ParentHash)
}

fn read_bytes(path: &str) -> Result<Vec<u8>, (i32, String)> {
    fs::read(path).map_err(|e| (2, format!("cannot read `{path}`: {e}")))
}

fn run_verify_tx(args: &[String]) -> CliResult {
    let options = parse_options(args)?;
    if options.files.len() != 1 {
        return Err((2, "verify-tx takes exactly one file".to_string()));
    }
    if options.validators.is_some() {
        return Err((2, "--validators is not used by verify-tx".to_string()));
    }
    let path = &options.files[0];
    let bytes = read_bytes(path)?;
    let tx = wire::decode_transaction_v7_strict(&bytes)
        .map_err(|e| (1, format!("{path}: wire: {e}")))?;

    let mut registry = ImplicitKeyRegistry::new();
    verify_tx(
        &tx,
        chain_id(&options),
        options.require_chain_id,
        &mut registry,
    )
    .map_err(|e| (1, format!("{path}: {e}")))?;

    println!(
        "ok: tx nonce={} from={} hash={}",
        tx.nonce,
        to_hex(&tx.from),
        to_hex(&txmod::compute_tx_hash(&tx))
    );
    Ok(())
}

fn run_verify_block(args: &[String]) -> CliResult {
    let options = parse_options(args)?;
    if options.files.len() != 1 {
        return Err((2, "verify-block takes exactly one file".to_string()));
    }
    if options.validators.is_none()
        && (options.verify_txs || options.require_qc || options.require_chain_id)
    {
        return Err((
            2,
            "--verify-txs, --require-qc, and --require-chain-id require --validators <FILE>"
                .to_string(),
        ));
    }
    let path = &options.files[0];
    let bytes = read_bytes(path)?;
    let block =
        wire::decode_block_v7_strict(&bytes).map_err(|e| (1, format!("{path}: wire: {e}")))?;
    let config = verifier_config(&options);
    let schedule = committee_schedule(&options);

    match &options.validators {
        Some(validators_path) => {
            let (validators, keys) = load_validators(validators_path)?;
            verify_block(&block, None, &validators, &keys, schedule, config)
                .map_err(|e| (1, format!("{path}: {e}")))?;
        }
        None => {
            structural_block(&block).map_err(|e| (1, format!("{path}: {e}")))?;
        }
    }

    println!(
        "ok: block height={} shard={} round={} hash={}",
        block.height,
        block.shard_id,
        block.round,
        to_hex(&block_hash::compute_block_hash_at(
            &block,
            config.chain_id,
            config.header_commit_activation_height,
        ))
    );
    Ok(())
}

fn run_verify_chain(args: &[String]) -> CliResult {
    let options = parse_options(args)?;
    if options.files.is_empty() {
        return Err((2, "verify-chain needs at least one file".to_string()));
    }
    if options.validators.is_none()
        && (options.verify_txs || options.require_qc || options.require_chain_id)
    {
        return Err((
            2,
            "--verify-txs, --require-qc, and --require-chain-id require --validators <FILE>"
                .to_string(),
        ));
    }
    let mut blocks = Vec::with_capacity(options.files.len());
    for path in &options.files {
        let bytes = read_bytes(path)?;
        let block =
            wire::decode_block_v7_strict(&bytes).map_err(|e| (1, format!("{path}: wire: {e}")))?;
        blocks.push(block);
    }
    let config = verifier_config(&options);
    let schedule = committee_schedule(&options);

    match &options.validators {
        Some(validators_path) => {
            let (validators, keys) = load_validators(validators_path)?;
            verify_chain(&blocks, &validators, &keys, schedule, config)
                .map_err(|e| (1, format!("chain: {e}")))?;
        }
        None => {
            verify_chain_structural(
                &blocks,
                config.chain_id,
                config.header_commit_activation_height,
            )
            .map_err(|e| (1, format!("chain: {e}")))?;
        }
    }

    println!("ok: {} blocks verified", blocks.len());
    Ok(())
}

#[derive(Default)]
struct SnapshotArgs {
    state_root: Option<String>,
    block: Option<String>,
    snapshot: Option<String>,
    proof: Option<String>,
    accounts: Option<String>,
}

#[derive(Default)]
struct ProofArgs {
    state_root: Option<String>,
    key: Option<String>,
    value: Option<String>,
    proof: Option<String>,
    absent: bool,
}

fn named_value(args: &[String], index: usize, flag: &str) -> Result<String, (i32, String)> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| (2, format!("{flag} needs a value")))
}

fn parse_snapshot_args(args: &[String]) -> Result<SnapshotArgs, (i32, String)> {
    let mut parsed = SnapshotArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state-root" => {
                let value = named_value(args, i, "--state-root")?;
                if parsed.state_root.replace(value).is_some() {
                    return Err((2, "--state-root given more than once".to_string()));
                }
                i += 2;
            }
            "--block" => {
                let value = named_value(args, i, "--block")?;
                if parsed.block.replace(value).is_some() {
                    return Err((2, "--block given more than once".to_string()));
                }
                i += 2;
            }
            "--snapshot" => {
                let value = named_value(args, i, "--snapshot")?;
                if parsed.snapshot.replace(value).is_some() {
                    return Err((2, "--snapshot given more than once".to_string()));
                }
                i += 2;
            }
            "--proof" => {
                let value = named_value(args, i, "--proof")?;
                if parsed.proof.replace(value).is_some() {
                    return Err((2, "--proof given more than once".to_string()));
                }
                i += 2;
            }
            "--accounts" => {
                let value = named_value(args, i, "--accounts")?;
                if parsed.accounts.replace(value).is_some() {
                    return Err((2, "--accounts given more than once".to_string()));
                }
                i += 2;
            }
            "-h" | "--help" => return Err((0, USAGE.to_string())),
            flag if flag.starts_with('-') => {
                return Err((2, format!("unknown option `{flag}`\n\n{USAGE}")))
            }
            positional => {
                return Err((
                    2,
                    format!("unexpected positional argument `{positional}`\n\n{USAGE}"),
                ))
            }
        }
    }
    Ok(parsed)
}

fn parse_proof_args(args: &[String]) -> Result<ProofArgs, (i32, String)> {
    let mut parsed = ProofArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state-root" => {
                let value = named_value(args, i, "--state-root")?;
                if parsed.state_root.replace(value).is_some() {
                    return Err((2, "--state-root given more than once".to_string()));
                }
                i += 2;
            }
            "--key" => {
                let value = named_value(args, i, "--key")?;
                if parsed.key.replace(value).is_some() {
                    return Err((2, "--key given more than once".to_string()));
                }
                i += 2;
            }
            "--value" => {
                let value = named_value(args, i, "--value")?;
                if parsed.value.replace(value).is_some() {
                    return Err((2, "--value given more than once".to_string()));
                }
                i += 2;
            }
            "--proof" => {
                let value = named_value(args, i, "--proof")?;
                if parsed.proof.replace(value).is_some() {
                    return Err((2, "--proof given more than once".to_string()));
                }
                i += 2;
            }
            "--absent" => {
                if parsed.absent {
                    return Err((2, "--absent given more than once".to_string()));
                }
                parsed.absent = true;
                i += 1;
            }
            "-h" | "--help" => return Err((0, USAGE.to_string())),
            flag if flag.starts_with('-') => {
                return Err((2, format!("unknown option `{flag}`\n\n{USAGE}")))
            }
            positional => {
                return Err((
                    2,
                    format!("unexpected positional argument `{positional}`\n\n{USAGE}"),
                ))
            }
        }
    }
    Ok(parsed)
}

fn run_verify_snapshot(args: &[String]) -> CliResult {
    match verify_snapshot_command(args) {
        Ok(()) => {
            println!("VERIFY_SNAPSHOT_RESULT=PASS");
            Ok(())
        }
        Err((0, message)) => Err((0, message)),
        Err((code, message)) => {
            println!("VERIFY_SNAPSHOT_RESULT=FAIL");
            Err((code, message))
        }
    }
}

fn verify_snapshot_command(args: &[String]) -> CliResult {
    let parsed = parse_snapshot_args(args)?;
    let cli_state_root = parsed
        .state_root
        .as_deref()
        .map(parse_hex32)
        .transpose()
        .map_err(|e| (2, e))?;
    if cli_state_root.is_none() && parsed.block.is_none() {
        return Err((
            2,
            "--state-root <hex32> or --block <block.bin> is required".to_string(),
        ));
    }
    let snapshot_path = parsed
        .snapshot
        .ok_or_else(|| (2, "--snapshot <json-file> is required".to_string()))?;
    match (&parsed.proof, &parsed.accounts) {
        (Some(_), Some(_)) => {
            return Err((
                2,
                "--proof and --accounts are mutually exclusive".to_string(),
            ))
        }
        (None, None) => {
            return Err((
                2,
                "verify-snapshot needs --proof <json-file> or --accounts <json-file>".to_string(),
            ))
        }
        _ => {}
    }

    let state_root = match (cli_state_root, parsed.block) {
        (Some(root), None) => root,
        (expected, Some(block_path)) => {
            let block_bytes = read_bytes(&block_path)?;
            let block = wire::decode_block_v7_strict(&block_bytes)
                .map_err(|e| (1, format!("{block_path}: wire: {e}")))?;
            let block_root = block.header().state_root;
            if let Some(cli_root) = expected {
                if cli_root != block_root {
                    return Err((
                        1,
                        format!(
                            "refused: --state-root {} does not match {} header state_root {}",
                            to_hex(&cli_root),
                            block_path,
                            to_hex(&block_root)
                        ),
                    ));
                }
            }
            block_root
        }
        (None, None) => {
            return Err((
                2,
                "--state-root <hex32> or --block <block.bin> is required".to_string(),
            ))
        }
    };

    let snapshot_text = fs::read_to_string(&snapshot_path)
        .map_err(|e| (2, format!("cannot read `{snapshot_path}`: {e}")))?;
    let snapshot =
        parse_snapshot_json(&snapshot_text).map_err(|e| (2, format!("{snapshot_path}: {e}")))?;
    let digest = snapshot.digest();

    match (parsed.proof, parsed.accounts) {
        (Some(proof_path), None) => {
            let proof_text = fs::read_to_string(&proof_path)
                .map_err(|e| (2, format!("cannot read `{proof_path}`: {e}")))?;
            let proof =
                parse_proof_json(&proof_text).map_err(|e| (2, format!("{proof_path}: {e}")))?;
            let verified = verify_state_root_against_snapshot(&state_root, &snapshot, &proof)
                .map_err(|e| (1, format!("refused: {e}")))?;
            println!(
                "ok: digest={} root={} key={}",
                to_hex(&verified),
                to_hex(&state_root),
                to_hex(&vc::commitment_key())
            );
            Ok(())
        }
        (None, Some(accounts_path)) => {
            let accounts_text = fs::read_to_string(&accounts_path)
                .map_err(|e| (2, format!("cannot read `{accounts_path}`: {e}")))?;
            let leaves = parse_accounts_json(&accounts_text)
                .map_err(|e| (2, format!("{accounts_path}: {e}")))?;
            verify_state_root_full(&state_root, &snapshot, &leaves)
                .map_err(|e| (1, format!("refused: {e}")))?;
            println!(
                "ok: digest={} root={} leaves={}",
                to_hex(&digest),
                to_hex(&state_root),
                leaves.len() + 1
            );
            Ok(())
        }
        _ => Err((
            2,
            "verify-snapshot needs exactly one of --proof or --accounts".to_string(),
        )),
    }
}

fn run_verify_proof(args: &[String]) -> CliResult {
    match verify_proof_command(args) {
        Ok(()) => {
            println!("VERIFY_PROOF_RESULT=PASS");
            Ok(())
        }
        Err((0, message)) => Err((0, message)),
        Err((code, message)) => {
            println!("VERIFY_PROOF_RESULT=FAIL");
            Err((code, message))
        }
    }
}

fn verify_proof_command(args: &[String]) -> CliResult {
    let parsed = parse_proof_args(args)?;
    let state_root_text = parsed
        .state_root
        .ok_or_else(|| (2, "--state-root <hex32> is required".to_string()))?;
    let state_root = parse_hex32(&state_root_text).map_err(|e| (2, e))?;
    let key_text = parsed
        .key
        .ok_or_else(|| (2, "--key <hex32> is required".to_string()))?;
    let key = parse_hex32(&key_text).map_err(|e| (2, e))?;
    let proof_path = parsed
        .proof
        .ok_or_else(|| (2, "--proof <json-file> is required".to_string()))?;
    let proof_text = fs::read_to_string(&proof_path)
        .map_err(|e| (2, format!("cannot read `{proof_path}`: {e}")))?;
    let proof = parse_proof_json(&proof_text).map_err(|e| (2, format!("{proof_path}: {e}")))?;

    if parsed.absent {
        if parsed.value.is_some() {
            return Err((2, "--value cannot be used with --absent".to_string()));
        }
        verify_commitment_exclusion(&state_root, &key, &proof)
            .map_err(|e| (1, format!("refused: {e}")))?;
        println!(
            "ok: key={} absent root={}",
            to_hex(&key),
            to_hex(&state_root)
        );
        return Ok(());
    }

    let value_text = parsed.value.ok_or_else(|| {
        (
            2,
            "--value <hex> is required (or pass --absent)".to_string(),
        )
    })?;
    let value = from_hex(strip_hex_prefix(&value_text))
        .map_err(|e| (2, format!("invalid --value hex: {e}")))?;

    if !vc::verify_proof(&state_root, &key, &value, &proof) {
        return Err((
            1,
            format!(
                "refused: no inclusion proof for key {} -> {} at state root {}",
                to_hex(&key),
                to_hex(&value),
                to_hex(&state_root)
            ),
        ));
    }
    println!(
        "ok: key={} value_len={} root={}",
        to_hex(&key),
        value.len(),
        to_hex(&state_root)
    );
    Ok(())
}

fn structural_block(block: &wire::Block) -> Result<(), VerifyError> {
    if !block.shard_headers_canonical() {
        return Err(VerifyError::Consensus(format!(
            "block {} has non-canonical shard_headers",
            block.height
        )));
    }
    if !block_hash::verify_order_merkle_root(block) {
        return Err(VerifyError::Hash(format!(
            "block {} order_merkle_root mismatch",
            block.height
        )));
    }
    if !block_hash::verify_cross_shard_msg_ids(block) {
        return Err(VerifyError::Hash(format!(
            "block {} contains a cross-shard message with an invalid msg_id",
            block.height
        )));
    }
    if block.cross_shard_out.iter().any(|msg| msg.trusted) {
        return Err(VerifyError::Consensus(format!(
            "block {} contains a cross-shard message with trusted=true",
            block.height
        )));
    }
    Ok(())
}

fn verify_chain_structural(
    blocks: &[wire::Block],
    chain_id: u64,
    header_commit_activation_height: u64,
) -> Result<(), VerifyError> {
    if blocks.is_empty() {
        return Err(VerifyError::Consensus("empty chain".to_string()));
    }
    let expected_shard = blocks[0].shard_id;
    let mut prev_height: Option<u64> = None;
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut prev_ts: Option<u64> = None;

    for block in blocks {
        if block.shard_id != expected_shard {
            return Err(VerifyError::Consensus(format!(
                "block {} shard_id mismatch (expected {}, got {})",
                block.height, expected_shard, block.shard_id
            )));
        }
        structural_block(block)?;
        if let Some(height) = prev_height {
            if block.height != height.saturating_add(1) {
                return Err(VerifyError::Consensus(format!(
                    "height discontinuity: expected {}, got {}",
                    height.saturating_add(1),
                    block.height
                )));
            }
        }
        if let Some(hash) = prev_hash {
            if block.prev_hash != hash {
                return Err(VerifyError::Consensus(format!(
                    "block {} prev_hash mismatch (expected {}, got {})",
                    block.height,
                    to_hex(&hash),
                    to_hex(&block.prev_hash)
                )));
            }
        }
        if let Some(ts) = prev_ts {
            if !block_hash::timestamp_within_bounds(ts, block.timestamp) {
                return Err(VerifyError::Consensus(format!(
                    "block {} timestamp {} out of bounds relative to parent {}",
                    block.height, block.timestamp, ts
                )));
            }
        }
        prev_hash = Some(block_hash::compute_block_hash_at(
            block,
            chain_id,
            header_commit_activation_height,
        ));
        prev_height = Some(block.height);
        prev_ts = Some(block.timestamp);
    }
    Ok(())
}

fn load_validators(path: &str) -> Result<(ValidatorSet, StaticPqKeyRegistry), (i32, String)> {
    let text = fs::read_to_string(path)
        .map_err(|e| (2, format!("cannot read validators `{path}`: {e}")))?;
    let mut set = ValidatorSet::new();
    let mut keys = StaticPqKeyRegistry::new();

    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 2 && fields.len() != 4 {
            return Err((
                2,
                format!(
                    "{path}:{}: expected `<id> <power> [<scheme> <pubkey>]`",
                    index + 1
                ),
            ));
        }
        let id = parse_hex32(fields[0]).map_err(|e| (2, format!("{path}:{}: {e}", index + 1)))?;
        let power = fields[1].parse::<u64>().map_err(|_| {
            (
                2,
                format!("{path}:{}: invalid power `{}`", index + 1, fields[1]),
            )
        })?;
        set.add(id, power);
        if fields.len() == 4 {
            let scheme_id = u8::from_str_radix(strip_hex_prefix(fields[2]), 16).map_err(|_| {
                (
                    2,
                    format!("{path}:{}: invalid scheme id `{}`", index + 1, fields[2]),
                )
            })?;
            let scheme = PqScheme::from_id(scheme_id)
                .map_err(|e| (2, format!("{path}:{}: {e}", index + 1)))?;
            let pubkey = from_hex(strip_hex_prefix(fields[3]))
                .map_err(|e| (2, format!("{path}:{}: invalid pubkey hex: {e}", index + 1)))?;
            keys.insert(id, scheme, pubkey);
        }
    }
    Ok((set, keys))
}

/// A parsed JSON value.
///
/// The verifier deliberately has no `serde_json` dependency. This parser
/// accepts RFC 8259 JSON and refuses everything it does not fully understand,
/// which is the right failure mode for a verification input: an ambiguous or
/// malformed document is an error, never a best-effort read.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

const MAX_JSON_DEPTH: usize = 64;

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> JsonParser<'a> {
    fn parse_document(text: &'a str) -> Result<Json, String> {
        let mut parser = Self {
            bytes: text.as_bytes(),
            pos: 0,
            depth: 0,
        };
        parser.skip_ws();
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(format!(
                "trailing bytes after the JSON document at offset {}",
                parser.pos
            ));
        }
        Ok(value)
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek() {
            if byte == b' ' || byte == b'\t' || byte == b'\n' || byte == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at offset {}",
                byte as char, self.pos
            ))
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b't') => {
                self.expect_keyword("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.expect_keyword("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.expect_keyword("null")?;
                Ok(Json::Null)
            }
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(format!(
                "unexpected byte `{}` at offset {}",
                other as char, self.pos
            )),
            None => Err("unexpected end of JSON input".to_string()),
        }
    }

    fn expect_keyword(&mut self, keyword: &str) -> Result<(), String> {
        let end = self.pos + keyword.len();
        if self.bytes.get(self.pos..end) == Some(keyword.as_bytes()) {
            self.pos = end;
            Ok(())
        } else {
            Err(format!("invalid JSON literal at offset {}", self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(format!("JSON nesting depth exceeds {MAX_JSON_DEPTH}"));
        }
        self.depth += 1;
        let res = self.parse_object_inner();
        self.depth -= 1;
        res
    }

    fn parse_object_inner(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut fields: Vec<(String, Json)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            if fields.iter().any(|(existing, _)| existing == &key) {
                return Err(format!("duplicate JSON key `{key}`"));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(fields));
                }
                Some(other) => {
                    return Err(format!(
                        "expected `,` or `}}` at offset {}, found `{}`",
                        self.pos, other as char
                    ))
                }
                None => return Err("unterminated JSON object".to_string()),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(format!("JSON nesting depth exceeds {MAX_JSON_DEPTH}"));
        }
        self.depth += 1;
        let res = self.parse_array_inner();
        self.depth -= 1;
        res
    }

    fn parse_array_inner(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                Some(other) => {
                    return Err(format!(
                        "expected `,` or `]` at offset {}, found `{}`",
                        self.pos, other as char
                    ))
                }
                None => return Err("unterminated JSON array".to_string()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| "unterminated JSON string".to_string())?;
            self.pos += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = self
                        .peek()
                        .ok_or_else(|| "unterminated JSON escape".to_string())?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.parse_unicode_escape()?),
                        other => return Err(format!("invalid JSON escape `\\{}`", other as char)),
                    }
                }
                0x00..=0x1F => return Err("raw control character in a JSON string".to_string()),
                _ if byte < 0x80 => out.push(byte as char),
                _ => {
                    let start = self.pos - 1;
                    let width = match byte {
                        0xC2..=0xDF => 2,
                        0xE0..=0xEF => 3,
                        0xF0..=0xF4 => 4,
                        _ => return Err("invalid UTF-8 in a JSON string".to_string()),
                    };
                    let end = start + width;
                    if end > self.bytes.len() {
                        return Err("truncated UTF-8 in a JSON string".to_string());
                    }
                    self.pos = end;
                    let text = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| "invalid UTF-8 in a JSON string".to_string())?;
                    out.push_str(text);
                }
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        let high = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            if self.bytes.get(self.pos) != Some(&b'\\')
                || self.bytes.get(self.pos + 1) != Some(&b'u')
            {
                return Err("high surrogate without a low surrogate".to_string());
            }
            self.pos += 2;
            let low = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err("invalid low surrogate".to_string());
            }
            let code_point = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            char::from_u32(code_point).ok_or_else(|| "invalid Unicode code point".to_string())
        } else if (0xDC00..=0xDFFF).contains(&high) {
            Err("lone low surrogate in a JSON string".to_string())
        } else {
            char::from_u32(high).ok_or_else(|| "invalid Unicode code point".to_string())
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let end = self.pos + 4;
        let digits = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| "truncated `\\u` escape".to_string())?;
        let mut value = 0u32;
        for &byte in digits {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err("invalid `\\u` escape digit".to_string()),
            };
            value = (value << 4) | digit as u32;
        }
        self.pos = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(format!("invalid JSON number at offset {start}")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let digits_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == digits_start {
                return Err("JSON number has no fraction digits".to_string());
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let digits_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == digits_start {
                return Err("JSON exponent has no digits".to_string());
            }
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid JSON number".to_string())?;
        Ok(Json::Number(raw.to_string()))
    }
}

fn json_field<'a>(fields: &'a [(String, Json)], name: &str) -> Result<&'a Json, String> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("missing JSON field `{name}`"))
}

fn json_allowed_and_required_fields(
    fields: &[(String, Json)],
    allowed: &[&str],
    required: &[&str],
) -> Result<(), String> {
    for (key, _) in fields {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unknown JSON field `{key}`"));
        }
    }
    for name in required {
        if !fields.iter().any(|(key, _)| key == name) {
            return Err(format!("missing JSON field `{name}`"));
        }
    }
    Ok(())
}

fn json_exact_fields(fields: &[(String, Json)], expected: &[&str]) -> Result<(), String> {
    json_allowed_and_required_fields(fields, expected, expected)
}

fn json_hex(fields: &[(String, Json)], name: &str) -> Result<Vec<u8>, String> {
    match json_field(fields, name)? {
        Json::String(text) => {
            from_hex(strip_hex_prefix(text)).map_err(|e| format!("field `{name}`: {e}"))
        }
        _ => Err(format!("field `{name}` must be a hex string")),
    }
}

fn json_opt_hex(fields: &[(String, Json)], name: &str) -> Result<Vec<u8>, String> {
    if !fields.iter().any(|(key, _)| key == name) {
        return Ok(Vec::new());
    }
    json_hex(fields, name)
}

fn json_opt_u64(fields: &[(String, Json)], name: &str) -> Result<u64, String> {
    let Some(val) = fields.iter().find(|(key, _)| key == name).map(|(_, v)| v) else {
        return Ok(0);
    };
    match val {
        Json::Number(raw) | Json::String(raw) => raw
            .parse::<u64>()
            .map_err(|_| format!("field `{name}` must be a u64")),
        _ => Err(format!("field `{name}` must be a u64")),
    }
}

const SNAPSHOT_REQUIRED_FIELDS: [&str; 13] = [
    "version",
    "tokens",
    "staking",
    "pmm",
    "contracts",
    "escrow",
    "governance",
    "oracle",
    "session_keys",
    "books",
    "bridge",
    "cross_shard",
    "xpc",
];

const SNAPSHOT_FIELDS: [&str; 18] = [
    "version",
    "tokens",
    "staking",
    "pmm",
    "contracts",
    "escrow",
    "governance",
    "oracle",
    "session_keys",
    "books",
    "bridge",
    "cross_shard",
    "xpc",
    "zkml",
    "cnvrf",
    "total_minted_nano",
    "evm_bindings",
    "pq_registry",
];

fn parse_snapshot_json(text: &str) -> Result<VerifierCommitmentSnapshot, String> {
    let Json::Object(fields) = JsonParser::parse_document(text)? else {
        return Err("snapshot must be a JSON object".to_string());
    };
    json_allowed_and_required_fields(&fields, &SNAPSHOT_FIELDS, &SNAPSHOT_REQUIRED_FIELDS)?;
    let version = match json_field(&fields, "version")? {
        Json::Number(raw) => raw
            .parse::<u32>()
            .map_err(|_| "field `version` must be a u32".to_string())?,
        _ => return Err("field `version` must be a number".to_string()),
    };
    Ok(VerifierCommitmentSnapshot {
        version,
        tokens: json_hex(&fields, "tokens")?,
        staking: json_hex(&fields, "staking")?,
        pmm: json_hex(&fields, "pmm")?,
        contracts: json_hex(&fields, "contracts")?,
        escrow: json_hex(&fields, "escrow")?,
        governance: json_hex(&fields, "governance")?,
        oracle: json_hex(&fields, "oracle")?,
        session_keys: json_hex(&fields, "session_keys")?,
        books: json_hex(&fields, "books")?,
        bridge: json_hex(&fields, "bridge")?,
        cross_shard: json_hex(&fields, "cross_shard")?,
        xpc: json_hex(&fields, "xpc")?,
        zkml: json_opt_hex(&fields, "zkml")?,
        cnvrf: json_opt_hex(&fields, "cnvrf")?,
        total_minted_nano: json_opt_u64(&fields, "total_minted_nano")?,
        evm_bindings: json_opt_hex(&fields, "evm_bindings")?,
        pq_registry: json_opt_hex(&fields, "pq_registry")?,
    })
}

fn parse_proof_json(text: &str) -> Result<MerkleProof, String> {
    let Json::Array(items) = JsonParser::parse_document(text)? else {
        return Err("proof must be a JSON array of hex nodes".to_string());
    };
    let mut nodes = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        match item {
            Json::String(node) => nodes.push(node),
            _ => return Err(format!("proof node {index} is not a hex string")),
        }
    }
    MerkleProof::from_nodes(&nodes)
}

/// Account leaves parsed from `--accounts`: `(32-byte key, value bytes)` pairs.
type AccountLeaves = Vec<([u8; 32], Vec<u8>)>;

fn parse_accounts_json(text: &str) -> Result<AccountLeaves, String> {
    let Json::Array(items) = JsonParser::parse_document(text)? else {
        return Err("accounts must be a JSON array".to_string());
    };
    let mut leaves = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        let Json::Object(fields) = item else {
            return Err(format!("account leaf {index} must be a JSON object"));
        };
        json_exact_fields(&fields, &["key", "value"])
            .map_err(|e| format!("account leaf {index}: {e}"))?;
        let key = json_hex(&fields, "key").map_err(|e| format!("account leaf {index}: {e}"))?;
        if key.len() != 32 {
            return Err(format!(
                "account leaf {index}: key must be 32 bytes, got {}",
                key.len()
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key);
        let value = json_hex(&fields, "value").map_err(|e| format!("account leaf {index}: {e}"))?;
        leaves.push((key_bytes, value));
    }
    Ok(leaves)
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

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("invalid hex digit `{}`", other as char)),
    }
}

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err("hex input has an odd number of digits".to_string());
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn strip_hex_prefix(text: &str) -> &str {
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text)
}

fn parse_hex32(text: &str) -> Result<[u8; 32], String> {
    let cleaned = strip_hex_prefix(text);
    let bytes = from_hex(cleaned).map_err(|e| format!("invalid hex id `{text}`: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "validator id `{text}` must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
