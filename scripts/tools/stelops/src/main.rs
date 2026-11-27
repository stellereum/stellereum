//! `stelops` — the ops tool for a Stellereum node's on-disk store.
//!
//! WHY THIS EXISTS
//! ---------------
//! The live cluster died twice over things that are invisible from the RPC:
//!
//!  1. A node carried a STALE CONSENSUS LOCK (height 285028, round 56) and
//!     resumed at round 56 while its peers were at round 0. The rule
//!     "never adopt a peer's round" means such a node can NEVER rejoin, and
//!     the only cure is to drop the persisted lock. The lock lives in the
//!     sled `meta` tree under the key `consensus`, bincode-encoded — nothing
//!     in the RPC surface exposes it.
//!  2. The chain epoch (and therefore the pubsub TOPIC) is derived from the
//!     genesis state root, which is also only in the store
//!     (`meta:genesis_state_root`). If two nodes derive different epochs they
//!     silently land on different topics and never exchange a message.
//!
//! So this tool reads the store directly. It is deliberately SEPARATE from the
//! `stellereum` crate: it depends on `sled` only, builds offline in seconds,
//! and can be shipped to a node without rebuilding the whole validator.
//!
//! SAFETY
//! ------
//! * `sled` takes an EXCLUSIVE file lock on the store. While the node runs,
//!   every command here fails with "could not acquire lock" — that is the
//!   intended behaviour, not a bug: a live store must never be rewritten.
//! * `clear-lock` and `compact` are the mutating commands. Both refuse
//!   without `--force`, both back up the previous state next to the store, and
//!   `clear-lock` never touches the finalized pointer (`finalized_blob`).
//!
//! USAGE
//! -----
//!   stelops checkpoint   <store-dir>              # the consensus checkpoint
//!   stelops genesis-root <store-dir>              # the stored genesis state root
//!   stelops meta         <store-dir> <key>        # raw meta value (hex)
//!   stelops doctor       <store-dir> [opts]       # everything, as JSON
//!   stelops clear-lock   <store-dir> --force      # drop the stale lock
//!   stelops compact      <store-dir> --force      # offline store compaction
//!   stelops diverge      <data-dir-A> <data-dir-B> [opts]  # offline fork diff
//!
//! `diverge` compares two node DATA dirs (the directories that hold
//! `store`, `store-shard1`, ...) shard by shard WITHOUT starting a node:
//! finalized height+hash, checkpoint height and genesis root per shard. Any
//! difference prints a `DIVERGENCE` line and the exit code is 1 — this is the
//! offline counterpart of the live `DIVERGENCE` log (same finalized hash but
//! different post-state roots is exactly what split the chain at #288000).
//! Both nodes MUST be stopped (sled takes an exclusive lock).
//!
//! doctor options:
//!   --shards <list>   the node's STELL_SHARDS value (default "0")
//!   --shard-id <n>     the shard the node validates (default 0)
//!   --text            human-readable output instead of JSON

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CONSENSUS_TOPIC_BASE: &str = "stellereum/consensus/v1";

const DEFAULT_SHARDS: &str = "0";
const DEFAULT_SHARD_ID: u32 = 0;

fn usage() -> &'static str {
    "stelops — Stellereum node store ops tool\n\
     \n\
     USAGE:\n\
     \x20 stelops checkpoint   <store-dir>              print the consensus checkpoint\n\
     \x20 stelops genesis-root <store-dir>              print the stored genesis state root\n\
     \x20 stelops meta         <store-dir> <key>        print a raw meta value (hex)\n\
     \x20 stelops doctor       <store-dir> [opts]       print the full diagnosis (JSON)\n\
     \x20 stelops clear-lock   <store-dir> --force      remove a stale consensus lock\n\
     \x20 stelops compact      <store-dir> --force      offline store rebuild/compaction\n\
     \x20 stelops diverge      <data-dir-A> <data-dir-B> [opts]  offline fork diff (exit 1 on any difference)\n\
     \n\
     DOCTOR OPTIONS:\n\
     \x20 --shards <list>    the node's STELL_SHARDS value (default \"0\")\n\
     \x20 --shard-id <n>     the shard the node validates (default 0)\n\
     \x20 --text             human-readable output instead of JSON\n\
     \n\
     NOTES:\n\
     \x20 * the store is LOCKED by a running node: every command fails with\n\
     \x20   \"could not acquire lock\" while the node is up. That is by design.\n\
     \x20 * clear-lock and compact are the mutating commands; both refuse without --force.\n"
}

fn die(msg: &str) -> ! {
    eprintln!("stelops: {}", msg);
    std::process::exit(2);
}

fn validate_store_dir(dir: &Path) -> Result<(), String> {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("store dir not found: {}", dir.display()));
        }
        Err(e) => {
            return Err(format!("cannot stat store dir {}: {e}", dir.display()));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "store dir {} is a symlink; refusing",
            dir.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!(
            "store path {} is not a directory",
            dir.display()
        ));
    }
    let db_path = dir.join("db");
    let db_meta = match std::fs::symlink_metadata(&db_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "not a stellereum store (no `db` file in {}): refusing to open it \
                 (sled would create an empty database)",
                dir.display()
            ));
        }
        Err(e) => {
            return Err(format!("cannot stat {}: {e}", db_path.display()));
        }
    };
    if db_meta.file_type().is_symlink() {
        return Err(format!(
            "store db file {} is a symlink; refusing",
            db_path.display()
        ));
    }
    if !db_meta.is_file() {
        return Err(format!(
            "store db path {} is not a regular file",
            db_path.display()
        ));
    }
    Ok(())
}

/// The store directory must look like a Stellereum store: a `db` file next to
/// the sled config. Opening a wrong path with sled would CREATE an empty
/// database, which is a silent, destructive surprise.
fn check_store(dir: &Path) {
    if let Err(e) = validate_store_dir(dir) {
        die(&e);
    }
}

fn open_db(dir: &Path) -> sled::Db {
    check_store(dir);
    sled::Config::new()
        .path(dir)
        .cache_capacity(64 * 1024 * 1024)
        .open()
        .unwrap_or_else(|e| {
            die(&format!(
                "cannot open store {}: {}\n\
                 hint: the node holds an EXCLUSIVE lock on the store while it runs — \
                 stop the service before running this command",
                dir.display(),
                e
            ))
        })
}

/// A decoded `stellereum::storage::ConsensusCheckpoint`.
///
/// bincode 1.3 (default config) layout, in field order:
///   height          u64  LE   (8 bytes)
///   round           u32  LE   (4 bytes)
///   locked_hash     Option<[u8;32]>  -> 1 byte tag (0/1) + 32 bytes when Some
///   locked_round    u32  LE   (4 bytes)
///   finalized_height u64 LE   (8 bytes)
///   finalized_hash  [u8;32]  (32 bytes)
/// Total: 89 bytes with a lock, 57 without.
#[derive(Debug, Clone)]
struct Checkpoint {
    height: u64,
    round: u32,
    locked_hash: Option<[u8; 32]>,
    locked_round: u32,
    finalized_height: u64,
    finalized_hash: [u8; 32],
    raw_len: usize,
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

fn decode_checkpoint(b: &[u8]) -> Option<Checkpoint> {
    if b.len() < 13 {
        return None;
    }
    let height = le_u64(b, 0);
    let round = le_u32(b, 8);
    let tag = b[12];
    let (locked_hash, off) = match tag {
        0 => (None, 13usize),
        1 => {
            if b.len() < 45 {
                return None;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&b[13..45]);
            (Some(h), 45usize)
        }
        _ => return None,
    };
    if b.len() < off + 4 + 8 + 32 {
        return None;
    }
    let locked_round = le_u32(b, off);
    let finalized_height = le_u64(b, off + 4);
    let mut finalized_hash = [0u8; 32];
    finalized_hash.copy_from_slice(&b[off + 12..off + 44]);
    Some(Checkpoint {
        height,
        round,
        locked_hash,
        locked_round,
        finalized_height,
        finalized_hash,
        raw_len: b.len(),
    })
}

fn hex_of(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

/// The chain epoch: the first 8 bytes of the genesis state root, hex.
/// Mirrors `stellereum::network::EpochTag::from_genesis`.
fn epoch_of(genesis_root: &[u8]) -> Option<String> {
    if genesis_root.len() < 8 {
        return None;
    }
    Some(hex_of(&genesis_root[..8]))
}

/// Mirrors `ShardRegistry::from_env_or` + `is_sharded`.
fn parse_shards(list: &str) -> BTreeSet<u32> {
    let mut ids = BTreeSet::new();
    for part in list.split(',') {
        if let Ok(v) = part.trim().parse::<u32>() {
            ids.insert(v);
        }
    }
    if ids.is_empty() {
        ids.insert(0);
    }
    ids
}

/// Mirrors `consensus_net::consensus_topic` / `consensus_topic_for_shard`.
fn topics_for(epoch: &str, shards: &BTreeSet<u32>) -> Vec<String> {
    let is_sharded = shards.len() > 1;
    shards
        .iter()
        .map(|id| {
            if is_sharded {
                format!("{CONSENSUS_TOPIC_BASE}/{epoch}/shard/{id}")
            } else {
                format!("{CONSENSUS_TOPIC_BASE}/{epoch}")
            }
        })
        .collect()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_opt_str(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("\"{}\"", json_escape(s)),
        None => "null".to_string(),
    }
}

struct Args {
    cmd: String,
    positional: Vec<String>,
    shards: String,
    shard_id: u32,
    text: bool,
    force: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().collect();
    let mut a = Args {
        cmd: String::new(),
        positional: Vec::new(),
        shards: DEFAULT_SHARDS.to_string(),
        shard_id: DEFAULT_SHARD_ID,
        text: false,
        force: false,
    };
    let mut it = argv.into_iter();
    it.next(); // argv[0] — the program path
    a.cmd = it.next().unwrap_or_default();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--shards" => a.shards = it.next().unwrap_or_else(|| die("--shards needs a value")),
            "--shard-id" => {
                let v = it.next().unwrap_or_else(|| die("--shard-id needs a value"));
                a.shard_id = v
                    .parse()
                    .unwrap_or_else(|_| die("--shard-id needs a number"));
            }
            "--text" => a.text = true,
            "--force" | "-f" | "--yes" => a.force = true,
            "--help" | "-h" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            other if other.starts_with("--") => die(&format!("unknown option: {other}")),
            other => a.positional.push(other.to_string()),
        }
    }
    a
}

fn store_dir(args: &Args) -> PathBuf {
    match args.positional.first() {
        Some(d) => PathBuf::from(d),
        None => die("missing <store-dir>"),
    }
}

fn main() -> ExitCode {
    let args = parse_args();
    match args.cmd.as_str() {
        "" | "help" | "--help" | "-h" => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        "checkpoint" => cmd_checkpoint(&args),
        "genesis-root" => cmd_genesis_root(&args),
        "meta" => cmd_meta(&args),
        "doctor" => cmd_doctor(&args),
        "clear-lock" => cmd_clear_lock(&args),
        "compact" => cmd_compact(&args),
        "diverge" => cmd_diverge(&args),
        other => {
            eprintln!("stelops: unknown command '{other}'\n");
            eprint!("{}", usage());
            ExitCode::from(2)
        }
    }
}

fn run_checkpoint(db: &sled::Db) -> Result<ExitCode, String> {
    let meta = db
        .open_tree("meta")
        .map_err(|e| format!("open meta tree: {e}"))?;
    let raw = meta
        .get(b"consensus")
        .map_err(|e| format!("read meta consensus: {e}"))?;
    match raw {
        None => {
            println!("NO_CHECKPOINT");
            Ok(ExitCode::SUCCESS)
        }
        Some(bytes) => match decode_checkpoint(&bytes) {
            Some(cp) => {
                println!(
                    "height={} round={} locked_hash={} locked_round={} finalized_height={} finalized_hash={} bytes={}",
                    cp.height,
                    cp.round,
                    cp.locked_hash
                        .map(|h| hex_of(&h))
                        .unwrap_or_else(|| "none".to_string()),
                    cp.locked_round,
                    cp.finalized_height,
                    hex_of(&cp.finalized_hash),
                    cp.raw_len
                );
                Ok(ExitCode::SUCCESS)
            }
            None => {
                println!("UNPARSEABLE bytes={} hex={}", bytes.len(), hex_of(&bytes));
                Ok(ExitCode::from(1))
            }
        },
    }
}

fn cmd_checkpoint(args: &Args) -> ExitCode {
    let dir = store_dir(args);
    let db = open_db(&dir);
    match run_checkpoint(&db) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stelops: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_genesis_root(db: &sled::Db) -> Result<ExitCode, String> {
    let meta = db
        .open_tree("meta")
        .map_err(|e| format!("open meta tree: {e}"))?;
    match meta
        .get(b"genesis_state_root")
        .map_err(|e| format!("read meta genesis_state_root: {e}"))?
    {
        None => {
            println!("NO_GENESIS_ROOT");
            Ok(ExitCode::from(1))
        }
        Some(bytes) => {
            println!("{}", hex_of(&bytes));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_genesis_root(args: &Args) -> ExitCode {
    let dir = store_dir(args);
    let db = open_db(&dir);
    match run_genesis_root(&db) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stelops: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_meta(db: &sled::Db, key: &str) -> Result<ExitCode, String> {
    let meta = db
        .open_tree("meta")
        .map_err(|e| format!("open meta tree: {e}"))?;
    match meta
        .get(key.as_bytes())
        .map_err(|e| format!("read meta {key}: {e}"))?
    {
        None => {
            println!("NO_SUCH_KEY");
            Ok(ExitCode::from(1))
        }
        Some(bytes) => {
            println!("{}", hex_of(&bytes));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_meta(args: &Args) -> ExitCode {
    let dir = store_dir(args);
    let key = match args.positional.get(1) {
        Some(k) => k.clone(),
        None => die("missing <key>"),
    };
    let db = open_db(&dir);
    match run_meta(&db, &key) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stelops: {e}");
            ExitCode::from(1)
        }
    }
}

#[allow(clippy::needless_borrow)] // GATE: hex_of takes &[u8]; h is [u8; N] by value so &h is required for unsized coercion (clippy misfires here)
fn run_doctor(dir: &Path, db: &sled::Db, args: &Args) -> Result<ExitCode, String> {
    let meta = db
        .open_tree("meta")
        .map_err(|e| format!("open meta tree: {e}"))?;

    let genesis = meta
        .get(b"genesis_state_root")
        .map_err(|e| format!("read meta genesis_state_root: {e}"))?;
    let epoch = genesis.as_deref().and_then(epoch_of);
    let shards = parse_shards(&args.shards);
    let is_sharded = shards.len() > 1;
    let topics: Vec<String> = match &epoch {
        Some(e) => topics_for(e, &shards),
        None => Vec::new(),
    };
    let own_topic = match (&epoch, is_sharded) {
        (Some(e), true) => Some(format!(
            "{CONSENSUS_TOPIC_BASE}/{e}/shard/{}",
            args.shard_id
        )),
        (Some(e), false) => Some(format!("{CONSENSUS_TOPIC_BASE}/{e}")),
        _ => None,
    };

    let cp_raw = meta
        .get(b"consensus")
        .map_err(|e| format!("read meta consensus: {e}"))?;
    let cp = cp_raw.as_deref().and_then(decode_checkpoint);

    let finalized = meta
        .get(b"finalized_blob")
        .map_err(|e| format!("read meta finalized_blob: {e}"))?;
    let finalized_ptr = finalized.as_deref().and_then(|b| {
        if b.len() >= 40 {
            Some((le_u64(b, 0), hex_of(&b[8..40])))
        } else {
            None
        }
    });

    if args.text {
        println!("store            : {}", dir.display());
        println!(
            "genesis_root     : {}",
            genesis
                .as_deref()
                .map(|h| hex_of(&h))
                .unwrap_or_else(|| "n/a".to_string())
        );
        println!(
            "epoch            : {}",
            epoch.clone().unwrap_or_else(|| "n/a".to_string())
        );
        println!("shards           : {:?}", shards);
        println!("is_sharded       : {}", is_sharded);
        println!("topics           : {}", topics.join(" "));
        println!(
            "own_topic        : {}",
            own_topic.clone().unwrap_or_else(|| "n/a".to_string())
        );
        match &cp {
            Some(c) => {
                println!("checkpoint height: {}", c.height);
                println!("checkpoint round : {}", c.round);
                println!(
                    "lock             : {}",
                    c.locked_hash
                        .map(|h| hex_of(&h)) // GATE: h is [u8; N] by value; &h coerces to &[u8], bare h does not
                        .unwrap_or_else(|| "none".to_string())
                );
                println!("lock round       : {}", c.locked_round);
                println!("finalized_height : {}", c.finalized_height);
            }
            None => println!("checkpoint       : none"),
        }
        match finalized_ptr {
            Some((h, hash)) => println!("finalized_pointer: height={} hash={}", h, hash),
            None => println!("finalized_pointer: n/a"),
        }
        return Ok(ExitCode::SUCCESS);
    }

    let cp_json = match &cp {
        Some(c) => format!(
            "{{\"height\":{},\"round\":{},\"locked_hash\":{},\"locked_round\":{},\"finalized_height\":{},\"finalized_hash\":\"{}\"}}",
            c.height,
            c.round,
            json_opt_str(c.locked_hash.as_ref().map(|h| hex_of(h)).as_deref()),
            c.locked_round,
            c.finalized_height,
            hex_of(&c.finalized_hash)
        ),
        None => "null".to_string(),
    };
    let topics_json = topics
        .iter()
        .map(|t| format!("\"{}\"", json_escape(t)))
        .collect::<Vec<_>>()
        .join(",");
    let finalized_json = match finalized_ptr {
        Some((h, hash)) => format!("{{\"height\":{},\"hash\":\"{}\"}}", h, hash),
        None => "null".to_string(),
    };

    println!(
        "{{\"store\":\"{}\",\"genesis_root\":{},\"epoch\":{},\"shards\":[{}],\"is_sharded\":{},\"topics\":[{}],\"own_topic\":{},\"checkpoint\":{},\"finalized_pointer\":{}}}",
        json_escape(&dir.display().to_string()),
        genesis
            .as_deref()
            .map(|g| format!("\"{}\"", hex_of(g)))
            .unwrap_or_else(|| "null".to_string()),
        json_opt_str(epoch.as_deref()),
        shards.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(","),
        is_sharded,
        topics_json,
        json_opt_str(own_topic.as_deref()),
        cp_json,
        finalized_json
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_doctor(args: &Args) -> ExitCode {
    let dir = store_dir(args);
    let db = open_db(&dir);
    match run_doctor(&dir, &db, args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stelops: {e}");
            ExitCode::from(1)
        }
    }
}

/// One shard's worth of fork-identity: everything two nodes must agree on
/// to be on the same fork at this shard.
struct ShardIdentity {
    #[allow(dead_code)] // GATE: fork-identity record retains shard+dir for operator reports
    shard: u32,
    #[allow(dead_code)] // GATE: fork-identity record retains shard+dir for operator reports
    store_dir: String,
    present: bool,
    error: Option<String>,
    finalized_height: Option<u64>,
    finalized_hash: Option<String>,
    checkpoint_height: Option<u64>,
    genesis_root: Option<String>,
    snapshot_height: Option<u64>,
    snapshot_digest: Option<String>,
}

fn read_shard_identity(data_dir: &Path, shard: u32) -> ShardIdentity {
    // Mirrors the node's store layout: shard 0 lives in `store`, every
    // other shard in `store-shard{id}`.
    let sub = if shard == 0 {
        "store".to_string()
    } else {
        format!("store-shard{shard}")
    };
    let dir = data_dir.join(&sub);
    let mut id = ShardIdentity {
        shard,
        store_dir: dir.display().to_string(),
        present: false,
        error: None,
        finalized_height: None,
        finalized_hash: None,
        checkpoint_height: None,
        genesis_root: None,
        snapshot_height: None,
        snapshot_digest: None,
    };
    if !dir.join("db").exists() {
        return id;
    }
    let db = match sled::Config::new()
        .path(dir.clone())
        .cache_capacity(16 * 1024 * 1024)
        .open()
    {
        Ok(db) => db,
        // Fail closed: a store that exists but cannot be opened (usually the
        // node is RUNNING and holds the exclusive lock) is NOT "empty" — it
        // is unreadable, and reporting AGREE for it would certify a fork as
        // healthy. Stop the node first.
        Err(e) => {
            id.error = Some(format!("cannot open (is the node running?): {e}"));
            return id;
        }
    };
    id.present = true;
    if let Ok(meta) = db.open_tree("meta") {
        if let Ok(Some(b)) = meta.get(b"finalized_blob") {
            if b.len() >= 40 {
                id.finalized_height = Some(le_u64(&b, 0));
                id.finalized_hash = Some(hex_of(&b[8..40]));
            }
        }
        if let Ok(Some(b)) = meta.get(b"consensus") {
            if let Some(cp) = decode_checkpoint(&b) {
                id.checkpoint_height = Some(cp.height);
            }
        }
        if let Ok(Some(b)) = meta.get(b"genesis_state_root") {
            id.genesis_root = Some(hex_of(&b));
        }
    }
    // Latest state snapshot: the full engine state at that height. Two nodes
    // that finalized the same hash but executed it differently (the #288000
    // shape) hold byte-different snapshots — this is the offline witness the
    // finalized hash alone cannot give (the hash commits to the PRE-state).
    // NOTE: snapshot keys are big-endian (`height.to_be_bytes()` in storage).
    if let Ok(state) = db.open_tree("state") {
        if let Ok(Some((k, v))) = state.last() {
            if k.len() == 8 {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                id.snapshot_height = Some(u64::from_be_bytes(h));
                id.snapshot_digest = Some(hex_of(blake3::hash(&v).as_bytes()));
            }
        }
    }
    id
}

/// `stelops diverge <data-dir-A> <data-dir-B> [--shards 0,1]`.
///
/// Offline fork comparator: reads each shard store's fork-identity from both
/// data dirs and prints one line per shard plus a `DIVERGENCE` line (and exit
/// code 1) for any shard where the nodes disagree. Read-only; both nodes
/// must be stopped (sled lock).
fn cmd_diverge(args: &Args) -> ExitCode {
    if args.positional.len() < 2 {
        die("diverge needs two data dirs: stelops diverge <data-dir-A> <data-dir-B>");
    }
    let dir_a = PathBuf::from(&args.positional[0]);
    let dir_b = PathBuf::from(&args.positional[1]);
    if !dir_a.exists() {
        die(&format!("data dir not found: {}", dir_a.display()));
    }
    if !dir_b.exists() {
        die(&format!("data dir not found: {}", dir_b.display()));
    }
    let shards = parse_shards(&args.shards);
    let mut diverged = 0u32;
    for shard in shards {
        let a = read_shard_identity(&dir_a, shard);
        let b = read_shard_identity(&dir_b, shard);
        let same = a.error.is_none()
            && b.error.is_none()
            && a.present == b.present
            && a.finalized_height == b.finalized_height
            && a.finalized_hash == b.finalized_hash
            && a.checkpoint_height == b.checkpoint_height
            && a.genesis_root == b.genesis_root
            && a.snapshot_height == b.snapshot_height
            && a.snapshot_digest == b.snapshot_digest;
        println!(
            "shard={} A finalized={}:{} checkpoint={} genesis={} snap={}:{} | B finalized={}:{} checkpoint={} genesis={} snap={}:{} | {}",
            shard,
            a.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
            a.finalized_hash.clone().unwrap_or_else(|| "none".to_string()),
            a.checkpoint_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
            a.genesis_root.clone().map(|g| g[..8.min(g.len())].to_string()).unwrap_or_else(|| "none".to_string()),
            a.snapshot_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
            a.snapshot_digest.clone().map(|g| g[..16.min(g.len())].to_string()).unwrap_or_else(|| "none".to_string()),
            b.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
            b.finalized_hash.clone().unwrap_or_else(|| "none".to_string()),
            b.checkpoint_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
            b.genesis_root.clone().map(|g| g[..8.min(g.len())].to_string()).unwrap_or_else(|| "none".to_string()),
            b.snapshot_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
            b.snapshot_digest.clone().map(|g| g[..16.min(g.len())].to_string()).unwrap_or_else(|| "none".to_string()),
            if same { "AGREE" } else { "DIVERGENCE" },
        );
        if !same {
            diverged += 1;
            if let Some(e) = a.error.as_deref().or(b.error.as_deref()) {
                println!("DIVERGENCE shard={}: unreadable store ({e}) — stop the node(s) and retry; refusing to certify", shard);
            }
            if a.finalized_height == b.finalized_height && a.finalized_hash != b.finalized_hash {
                println!(
                    "DIVERGENCE shard={}: SAME height {} but different finalized hash (A={} B={}) — a true fork, not lag",
                    shard,
                    a.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
                    a.finalized_hash.unwrap_or_else(|| "none".to_string()),
                    b.finalized_hash.unwrap_or_else(|| "none".to_string()),
                );
            }
            if a.finalized_height != b.finalized_height {
                println!(
                    "DIVERGENCE shard={}: finalized height A={} B={} (one side is behind, not forked)",
                    shard,
                    a.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
                    b.finalized_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
                );
            }
            if a.genesis_root != b.genesis_root {
                println!(
                    "DIVERGENCE shard={}: genesis roots differ (different chains/networks)",
                    shard
                );
            }
            if a.snapshot_height == b.snapshot_height && a.snapshot_digest != b.snapshot_digest {
                println!(
                    "DIVERGENCE shard={}: same finalized hash but state snapshots at height {} differ (A={} B={}) — execution diverged, the finalized hash alone cannot see it",
                    shard,
                    a.snapshot_height.map(|h| h.to_string()).unwrap_or_else(|| "none".to_string()),
                    a.snapshot_digest.clone().unwrap_or_else(|| "none".to_string()),
                    b.snapshot_digest.clone().unwrap_or_else(|| "none".to_string()),
                );
            }
        }
    }
    if diverged > 0 {
        println!("DIVERGENCE: {diverged} shard(s) disagree — resync the minority side from a canonical snapshot (never auto-heal)");
        ExitCode::from(1)
    } else {
        println!("AGREE: all shards identical");
        ExitCode::SUCCESS
    }
}

fn run_clear_lock(dir: &Path, db: &sled::Db) -> Result<ExitCode, String> {
    let meta = db
        .open_tree("meta")
        .map_err(|e| format!("open meta tree: {e}"))?;
    let raw = match meta
        .get(b"consensus")
        .map_err(|e| format!("read meta consensus: {e}"))?
    {
        None => {
            println!("NO_CHECKPOINT nothing to clear");
            return Ok(ExitCode::SUCCESS);
        }
        Some(b) => b,
    };
    let cp = decode_checkpoint(&raw);
    // Back the bytes up next to the store (the store dir itself is sled-managed;
    // the parent is not).
    let backup_dir = dir.parent().unwrap_or(Path::new("."));
    let backup = backup_dir.join("consensus-checkpoint.bak");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stamped = backup_dir.join(format!("consensus-checkpoint.bak.{stamp}"));
    let _ = std::fs::copy(&backup, &stamped);
    std::fs::write(&stamped, &raw)
        .map_err(|e| format!("could not write the backup {}: {e}", stamped.display()))?;
    meta.remove(b"consensus")
        .map_err(|e| format!("remove consensus key: {e}"))?;
    db.flush().map_err(|e| format!("flush store: {e}"))?;
    println!("CLEARED");
    println!("backup: {}", stamped.display());
    match cp {
        Some(c) => println!(
            "removed: height={} round={} locked_hash={} locked_round={}",
            c.height,
            c.round,
            c.locked_hash
                .map(|h| hex_of(&h))
                .unwrap_or_else(|| "none".to_string()),
            c.locked_round
        ),
        None => println!("removed: unparseable checkpoint ({} bytes)", raw.len()),
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_clear_lock(args: &Args) -> ExitCode {
    let dir = store_dir(args);
    if !args.force {
        eprintln!(
            "stelops: clear-lock REFUSES without --force.\n\
             It removes the persisted consensus lock (height/round/locked hash) from\n\
             {}\n\
             The node MUST be stopped (the store is locked while it runs) and the\n\
             node MUST be far from its peers (the lock is the only thing keeping it\n\
             from rejoining). The finalized pointer is NOT touched.",
            dir.display()
        );
        return ExitCode::from(2);
    }
    let db = open_db(&dir);
    match run_clear_lock(&dir, &db) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("stelops: {e}");
            ExitCode::from(1)
        }
    }
}

struct CompactStats {
    trees: usize,
    keys: u64,
    before_bytes: u64,
    after_bytes: u64,
    backup_path: PathBuf,
}

fn sibling_path(dir: &Path, suffix: &str) -> Result<PathBuf, String> {
    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        let parent = dir.parent().unwrap_or_else(|| Path::new("."));
        return Ok(parent.join(format!("{name}{suffix}")));
    }
    let canon = std::fs::canonicalize(dir)
        .map_err(|e| format!("cannot resolve store path {}: {e}", dir.display()))?;
    let name = canon
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("store path has no directory name: {}", canon.display()))?;
    let parent = canon.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(format!("{name}{suffix}")))
}

fn dir_size(path: &Path) -> std::io::Result<u64> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_file() {
        return Ok(meta.len());
    }
    if !meta.is_dir() {
        return Ok(0);
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let child_meta = std::fs::symlink_metadata(entry.path())?;
        if child_meta.is_file() {
            total = total.saturating_add(child_meta.len());
        } else if child_meta.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        }
    }
    Ok(total)
}

fn tree_digest(tree: &sled::Tree) -> Result<(u64, [u8; 32]), String> {
    let mut count = 0u64;
    let mut hasher = blake3::Hasher::new();
    for kv in tree.iter() {
        let (k, v) = kv.map_err(|e| format!("read error while verifying tree: {e}"))?;
        count += 1;
        hasher.update(&(k.len() as u64).to_le_bytes());
        hasher.update(&k);
        hasher.update(&(v.len() as u64).to_le_bytes());
        hasher.update(&v);
    }
    Ok((count, *hasher.finalize().as_bytes()))
}

fn unique_backup_path(dir: &Path, unix_ts: u64) -> Result<PathBuf, String> {
    let base = sibling_path(dir, &format!(".pre-compact.{unix_ts}"))?;
    if !base.exists() {
        return Ok(base);
    }
    for idx in 1u64..1000 {
        let candidate = sibling_path(dir, &format!(".pre-compact.{unix_ts}.{idx}"))?;
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "backup path already exists for timestamp {unix_ts}"
    ))
}

fn run_compact(dir: &Path, force: bool) -> Result<CompactStats, String> {
    validate_store_dir(dir)?;
    if !force {
        return Err(format!(
            "compact REFUSES without --force (would rebuild {} and move original to backup)",
            dir.display()
        ));
    }

    let tmp_dir = sibling_path(dir, ".compact.tmp")?;
    if tmp_dir.exists() {
        if tmp_dir.join("db").exists() {
            let stale = sled::open(&tmp_dir).map_err(|e| {
                format!(
                    "stale compact temp dir {} cannot be opened (live lock?): {e}",
                    tmp_dir.display()
                )
            })?;
            drop(stale);
        }
        if tmp_dir.is_dir() {
            std::fs::remove_dir_all(&tmp_dir).map_err(|e| {
                format!(
                    "cannot remove stale compact temp dir {}: {e}",
                    tmp_dir.display()
                )
            })?;
        } else {
            std::fs::remove_file(&tmp_dir).map_err(|e| {
                format!(
                    "cannot remove stale compact temp file {}: {e}",
                    tmp_dir.display()
                )
            })?;
        }
    }

    let before_bytes =
        dir_size(dir).map_err(|e| format!("cannot measure store {}: {e}", dir.display()))?;

    let src_db = sled::open(dir).map_err(|e| {
        format!(
            "cannot open store {}: {e} (hint: stop the running node before compacting)",
            dir.display()
        )
    })?;
    let dst_db = match sled::open(&tmp_dir) {
        Ok(db) => db,
        Err(e) => {
            drop(src_db);
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!(
                "cannot create compact temp store {}: {e}",
                tmp_dir.display()
            ));
        }
    };

    let mut tree_names: Vec<Vec<u8>> = src_db
        .tree_names()
        .into_iter()
        .map(|n| n.to_vec())
        .collect();
    tree_names.sort();

    let mut expected_trees: Vec<(Vec<u8>, u64, [u8; 32])> = Vec::with_capacity(tree_names.len());
    let mut total_keys = 0u64;

    const BATCH_LIMIT: usize = 4096;
    for name in &tree_names {
        let src_tree = match src_db.open_tree(name) {
            Ok(t) => t,
            Err(e) => {
                drop(dst_db);
                drop(src_db);
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(format!(
                    "cannot open source tree {}: {e}",
                    String::from_utf8_lossy(name)
                ));
            }
        };
        let dst_tree = match dst_db.open_tree(name) {
            Ok(t) => t,
            Err(e) => {
                drop(dst_db);
                drop(src_db);
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(format!(
                    "cannot open destination tree {}: {e}",
                    String::from_utf8_lossy(name)
                ));
            }
        };

        let mut count = 0u64;
        let mut hasher = blake3::Hasher::new();
        let mut batch = sled::Batch::default();
        let mut pending = 0usize;

        for kv in src_tree.iter() {
            let (k, v) = match kv {
                Ok(pair) => pair,
                Err(e) => {
                    drop(dst_db);
                    drop(src_db);
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(format!(
                        "cannot iterate source tree {}: {e}",
                        String::from_utf8_lossy(name)
                    ));
                }
            };
            count += 1;
            hasher.update(&(k.len() as u64).to_le_bytes());
            hasher.update(&k);
            hasher.update(&(v.len() as u64).to_le_bytes());
            hasher.update(&v);
            batch.insert(k.as_ref(), v.as_ref());
            pending += 1;
            if pending >= BATCH_LIMIT {
                if let Err(e) = dst_tree.apply_batch(std::mem::take(&mut batch)) {
                    drop(dst_db);
                    drop(src_db);
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                    return Err(format!(
                        "cannot write batch to destination tree {}: {e}",
                        String::from_utf8_lossy(name)
                    ));
                }
                pending = 0;
            }
        }
        if pending > 0 {
            if let Err(e) = dst_tree.apply_batch(batch) {
                drop(dst_db);
                drop(src_db);
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(format!(
                    "cannot flush final batch to destination tree {}: {e}",
                    String::from_utf8_lossy(name)
                ));
            }
        }
        total_keys += count;
        expected_trees.push((name.clone(), count, *hasher.finalize().as_bytes()));
    }

    if let Err(e) = src_db.flush() {
        drop(dst_db);
        drop(src_db);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("cannot flush source store: {e}"));
    }
    if let Err(e) = dst_db.flush() {
        drop(dst_db);
        drop(src_db);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("cannot flush compacted store: {e}"));
    }

    let mut dst_tree_names: Vec<Vec<u8>> = dst_db
        .tree_names()
        .into_iter()
        .map(|n| n.to_vec())
        .collect();
    dst_tree_names.sort();
    if dst_tree_names != tree_names {
        drop(dst_db);
        drop(src_db);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!(
            "compacted tree set mismatch: expected {} trees, got {}",
            tree_names.len(),
            dst_tree_names.len()
        ));
    }

    for (name, expected_count, expected_digest) in &expected_trees {
        let dst_tree = match dst_db.open_tree(name) {
            Ok(t) => t,
            Err(e) => {
                drop(dst_db);
                drop(src_db);
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(format!(
                    "cannot reopen compacted tree {}: {e}",
                    String::from_utf8_lossy(name)
                ));
            }
        };
        let (actual_count, actual_digest) = match tree_digest(&dst_tree) {
            Ok(res) => res,
            Err(e) => {
                drop(dst_db);
                drop(src_db);
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return Err(e);
            }
        };
        if actual_count != *expected_count || actual_digest != *expected_digest {
            drop(dst_db);
            drop(src_db);
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(format!(
                "compaction verification mismatch on tree {}: src=({}, {}) dst=({}, {})",
                String::from_utf8_lossy(name),
                expected_count,
                hex_of(expected_digest),
                actual_count,
                hex_of(&actual_digest)
            ));
        }
    }

    if let Err(e) = dst_db.flush() {
        drop(dst_db);
        drop(src_db);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(format!("cannot flush verified compacted store: {e}"));
    }

    drop(dst_db);
    drop(src_db);

    let unix_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_path = unique_backup_path(dir, unix_ts)?;

    std::fs::rename(dir, &backup_path).map_err(|e| {
        format!(
            "cannot move original store {} to {}: {e}",
            dir.display(),
            backup_path.display()
        )
    })?;
    if let Err(e) = std::fs::rename(&tmp_dir, dir) {
        let rollback = std::fs::rename(&backup_path, dir);
        return Err(format!(
            "cannot promote compacted store {} -> {}: {e} (rollback: {:?})",
            tmp_dir.display(),
            dir.display(),
            rollback
        ));
    }

    let after_bytes = dir_size(dir)
        .map_err(|e| format!("cannot measure compacted store {}: {e}", dir.display()))?;

    Ok(CompactStats {
        trees: tree_names.len(),
        keys: total_keys,
        before_bytes,
        after_bytes,
        backup_path,
    })
}

fn cmd_compact(args: &Args) -> ExitCode {
    let dir = store_dir(args);
    check_store(&dir);
    if !args.force {
        eprintln!(
            "stelops: compact REFUSES without --force.\n\
             It exports and verifies every tree in {} into a fresh sled DB,\n\
             moves the original store to a timestamped backup, and swaps the\n\
             compacted DB into place. The node MUST be stopped.",
            dir.display()
        );
        return ExitCode::from(2);
    }
    match run_compact(&dir, args.force) {
        Ok(stats) => {
            println!(
                "COMPACTED trees={} keys={} before_bytes={} after_bytes={}",
                stats.trees, stats.keys, stats.before_bytes, stats.after_bytes
            );
            println!("backup: {}", stats.backup_path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("stelops: compact failed: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path =
                std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn snapshot_db(dir: &Path) -> BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> {
        let db = sled::open(dir).expect("open db for snapshot");
        let mut out = BTreeMap::new();
        for name in db.tree_names() {
            let tree = db.open_tree(&name).expect("open tree");
            let mut entries = BTreeMap::new();
            for kv in tree.iter() {
                let (k, v) = kv.expect("iter kv");
                entries.insert(k.to_vec(), v.to_vec());
            }
            out.insert(name.to_vec(), entries);
        }
        out
    }

    #[test]
    fn doctor_defaults_match_single_shard_testnet() {
        assert_eq!(DEFAULT_SHARDS, "0");
        assert_eq!(DEFAULT_SHARD_ID, 0);
        let shards = parse_shards(DEFAULT_SHARDS);
        assert_eq!(shards.len(), 1);
        assert!(shards.contains(&0));
        assert_eq!(
            topics_for("0123456789abcdef", &shards),
            vec!["stellereum/consensus/v1/0123456789abcdef".to_string()]
        );
    }

    #[test]
    fn compact_refuses_without_force_and_missing_store() {
        let tmp = TempDir::new("stelops-compact-refuse");
        let empty = tmp.0.join("not-a-store");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(run_compact(&empty, true).is_err());

        let store = tmp.0.join("store");
        let db = sled::open(&store).unwrap();
        db.insert(b"k", b"v").unwrap();
        db.flush().unwrap();
        drop(db);

        let err = run_compact(&store, false)
            .err()
            .expect("must fail without --force");
        assert!(err.contains("--force"));
        assert!(!sibling_path(&store, ".compact.tmp").unwrap().exists());
    }

    #[test]
    fn compact_fails_when_store_is_locked() {
        let tmp = TempDir::new("stelops-compact-locked");
        let store = tmp.0.join("store");
        let db = sled::open(&store).unwrap();
        db.insert(b"k", b"v").unwrap();
        db.flush().unwrap();

        let err = run_compact(&store, true)
            .err()
            .expect("must fail while store is open/locked");
        assert!(err.contains("cannot open store"));
        drop(db);
    }

    #[test]
    fn compact_preserves_all_trees_and_shrinks_deleted_entries() {
        let tmp = TempDir::new("stelops-compact-ok");
        let store = tmp.0.join("store");
        {
            let db = sled::open(&store).unwrap();
            db.insert(b"default_k1", b"default_v1").unwrap();

            let meta = db.open_tree("meta").unwrap();
            meta.insert(b"genesis_state_root", &[0xaa; 32]).unwrap();
            meta.insert(b"finalized_blob", &[0xbb; 40][..]).unwrap();

            let blocks = db.open_tree("blocks").unwrap();
            let payload = vec![0x5cu8; 4096];
            for i in 0u32..1000 {
                blocks.insert(i.to_be_bytes(), payload.as_slice()).unwrap();
            }
            blocks.flush().unwrap();
            for i in 0u32..995 {
                blocks.remove(i.to_be_bytes()).unwrap();
            }

            let empty_tree = db.open_tree("headers").unwrap();
            empty_tree.flush().unwrap();
            db.flush().unwrap();
        }

        // Plant a stale `.compact.tmp` directory to verify safe cleanup.
        let stale_tmp = sibling_path(&store, ".compact.tmp").unwrap();
        {
            let stale_db = sled::open(&stale_tmp).unwrap();
            stale_db.insert(b"stale", b"1").unwrap();
            stale_db.flush().unwrap();
        }

        let expected = snapshot_db(&store);
        let stats = run_compact(&store, true).expect("compact should succeed");
        assert!(stats.backup_path.exists());
        assert!(stats
            .backup_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(".pre-compact."));
        assert!(!stale_tmp.exists());
        assert!(
            stats.after_bytes < stats.before_bytes,
            "expected compacted size ({}) < original size ({})",
            stats.after_bytes,
            stats.before_bytes
        );

        let actual = snapshot_db(&store);
        assert_eq!(actual, expected);
    }

    #[cfg(unix)]
    #[test]
    fn validate_store_dir_refuses_symlink_directory() {
        let tmp = TempDir::new("stelops-symlink");
        let real_store = tmp.0.join("real-store");
        let db = sled::open(&real_store).unwrap();
        db.insert(b"k", b"v").unwrap();
        db.flush().unwrap();
        drop(db);

        validate_store_dir(&real_store).expect("real store dir should validate");

        let link_store = tmp.0.join("link-store");
        std::os::unix::fs::symlink(&real_store, &link_store).unwrap();
        let err = validate_store_dir(&link_store)
            .err()
            .expect("symlink store dir must be refused");
        assert!(err.contains("symlink"), "unexpected error: {err}");

        let dangling = tmp.0.join("dangling-store");
        std::os::unix::fs::symlink(tmp.0.join("missing"), &dangling).unwrap();
        let err = validate_store_dir(&dangling)
            .err()
            .expect("dangling symlink must be refused");
        assert!(err.contains("symlink"), "unexpected error: {err}");
    }
}
