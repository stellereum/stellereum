use bincode::Options;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use stellereum::consensus::{consensus_chain_id, VoteKind};
use stellereum::sharding::Block;
use stellereum::storage::{BlockHash, Storage};

const MAX_BLOCK_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CHAIN_BLOCKS: usize = 1024;
const USAGE: &str = "usage: stellereum-ledger-tool inspect-block <bincode-file> <chain-id>\n       stellereum-ledger-tool verify-block <bincode-file> <chain-id> <expected-hash-hex>\n       stellereum-ledger-tool verify-chain current-v1 <chain-id> <block-file> <block-file> [block-file...]\n       stellereum-ledger-tool verify-store [--in-place] <store-dir> <chain-id>\n       stellereum-ledger-tool repair|export [arguments...]\ncurrent-v1 means the full current node Block encoded by bincode fixed-int; legacy formats are not supported\ninput must be a stable, independent current-format block file, not a live store or a file being written; no snapshot or concurrency protection is provided\ninput limit: 32 MiB per block, 1024 blocks per chain; decoded heap and hash computation are not bounded by this limit; use OS resource limits for untrusted input";

fn decode_block(bytes: &[u8]) -> Result<Block, String> {
    if bytes.len() as u64 > MAX_BLOCK_BYTES {
        return Err("block exceeds 32 MiB limit".into());
    }
    // bincode::serialize, used by Storage::put_block, uses fixed integer
    // encoding. Reject trailing bytes and legacy tolerance: the latter can
    // interpret a truncated current block as an older block. The byte budget
    // is the actual input length, not a guarantee on decoded heap allocations.
    let block: Block = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("cannot decode current-format block: {e}"))?;
    let canonical = bincode::serialize(&block)
        .map_err(|e| format!("cannot re-encode current-format block: {e}"))?;
    if canonical != bytes {
        return Err("non-canonical current-format block encoding".into());
    }
    Ok(block)
}

fn read_block(path: &Path) -> Result<Block, String> {
    let link_meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat input: {e}"))?;
    if link_meta.file_type().is_symlink() {
        return Err(format!("refusing symlinked input: {}", path.display()));
    }
    if !link_meta.is_file() {
        return Err("input must be a regular file, not a store directory".into());
    }
    let file = File::open(path).map_err(|e| format!("cannot open input: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot stat input: {e}"))?;
    if !metadata.is_file() {
        return Err("input must be a regular file, not a store directory".into());
    }
    if metadata.len() > MAX_BLOCK_BYTES {
        return Err("block exceeds 32 MiB limit".into());
    }
    decode_block(&read_bounded(file)?)
}

fn read_bounded(mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        // Read at most one byte beyond the limit even if the file grows.
        let remaining = MAX_BLOCK_BYTES as usize - bytes.len();
        let count = chunk.len().min(remaining + 1);
        let n = match reader.read(&mut chunk[..count]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("cannot read input: {e}")),
        };
        if n == 0 {
            return Ok(bytes);
        }
        if n > remaining {
            return Err("block exceeds 32 MiB limit".into());
        }
        bytes
            .try_reserve_exact(n)
            .map_err(|e| format!("cannot allocate input buffer: {e}"))?;
        bytes.extend_from_slice(&chunk[..n]);
    }
}

fn expected_hash(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("expected hash must be 64 hex digits".into());
    }
    let bytes = hex::decode(value).map_err(|_| "expected hash must be 64 hex digits")?;
    bytes
        .try_into()
        .map_err(|_| "expected hash must be 64 hex digits".into())
}

fn check_hash(computed: [u8; 32], expected: [u8; 32]) -> Result<(), String> {
    if computed != expected {
        return Err(format!(
            "block hash mismatch: computed {}",
            hex::encode(computed)
        ));
    }
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("repair") | Some("export") => Err("refused: no safe repair/export implementation; requires an offline, consistent independent copy, validated recovery procedure, and an explicitly authorized destination; this tool never opens a store".into()),
        Some("inspect-block") if args.len() == 3 => examine(&args[1], &args[2], None),
        Some("verify-block") if args.len() == 4 => {
            let expected = expected_hash(&args[3])?;
            examine(&args[1], &args[2], Some(expected))
        }
        Some("verify-chain") if args.len() >= 5 => verify_chain(&args[1], &args[2], &args[3..]),
        Some("verify-store") => {
            let mut in_place = false;
            let mut positional: Vec<&str> = Vec::new();
            for arg in &args[1..] {
                if arg == "--in-place" {
                    if in_place {
                        return Err(USAGE.into());
                    }
                    in_place = true;
                } else if arg.starts_with('-') {
                    return Err(USAGE.into());
                } else {
                    positional.push(arg.as_str());
                }
            }
            if positional.len() != 2 {
                return Err(USAGE.into());
            }
            verify_store(Path::new(positional[0]), positional[1], in_place)
        }
        _ => Err(USAGE.into()),
    }
}

fn parse_chain_id(chain_id: &str) -> Result<u64, String> {
    let chain_id: u64 = chain_id
        .parse()
        .map_err(|_| "chain-id must be an unsigned integer")?;
    if chain_id == 0 {
        return Err("chain-id must be nonzero (the node substitutes its default for zero)".into());
    }
    Ok(chain_id)
}

fn verify_chain(format: &str, chain_id: &str, paths: &[String]) -> Result<(), String> {
    if format != "current-v1" {
        return Err("unsupported block format; expected current-v1".into());
    }
    if paths.len() > MAX_CHAIN_BLOCKS {
        return Err("chain exceeds 1024 block limit".into());
    }
    let chain_id = parse_chain_id(chain_id)?;
    std::env::set_var("STELL_CHAIN_ID", chain_id.to_string());
    let mut previous: Option<(u64, u32, [u8; 32])> = None;
    for path in paths {
        let block = read_block(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
        if let Some((height, shard, hash)) = previous {
            if height.checked_add(1) != Some(block.height) {
                return Err(format!("{path}: height is not consecutive after {height}"));
            }
            if block.shard_id != shard {
                return Err(format!("{path}: shard differs from preceding block"));
            }
            if block.prev_hash != hash {
                return Err(format!(
                    "{path}: parent hash does not match computed preceding block hash"
                ));
            }
        }
        let hash = block.compute_hash();
        previous = Some((block.height, block.shard_id, hash));
    }
    let (height, shard, hash) = previous.ok_or("no blocks supplied")?;
    println!("consistent unanchored segment: {} blocks, ending height {height}, shard {shard}, chain id {chain_id}", paths.len());
    println!("computed tip hash: {}", hex::encode(hash));
    println!("checked: current-v1 canonical encoding, consecutive heights, same shard, and parent links to computed block hashes");
    println!("not checked: trusted anchor, authenticity, signatures, QC, state, finality, consensus validity, or byte-for-byte integrity; a fabricated chain can pass");
    println!("input must be independent stable files; concurrent changes are not detected");
    println!("input limit: 32 MiB per block, 1024 blocks; decoded heap and hash computation are not bounded by this limit");
    Ok(())
}

fn examine(path: &str, chain_id: &str, expected: Option<[u8; 32]>) -> Result<(), String> {
    let chain_id = parse_chain_id(chain_id)?;
    let block = read_block(Path::new(path))?;
    // The CLI process is single-threaded and computes no consensus hash
    // before setting the node's one-time chain-id source.
    std::env::set_var("STELL_CHAIN_ID", chain_id.to_string());
    let hash = block.compute_hash();
    if let Some(expected) = expected {
        check_hash(hash, expected)?;
    }
    println!(
        "height: {}\nshard: {}\nchain id: {}\ncomputed block hash: {}",
        block.height,
        block.shard_id,
        chain_id,
        hex::encode(hash)
    );
    if expected.is_some() {
        println!("block hash matches supplied value");
    } else {
        println!("inspection only: no expected hash supplied");
    }
    println!("scope: computed block hash and optional comparison only, not byte-for-byte integrity; no QC, finality, signatures, state, store integrity, or chain validation");
    println!("input must be an independent stable file; concurrent changes are not detected");
    println!(
        "input limit: 32 MiB; decoded heap and hash computation are not bounded by this limit"
    );
    Ok(())
}

static TEMP_STORE_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempStoreGuard {
    path: PathBuf,
}

impl Drop for TempStoreGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn create_temp_store_dir() -> Result<TempStoreGuard, String> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for _ in 0..16 {
        let seq = TEMP_STORE_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("stellereum-verify-store-{pid}-{nanos}-{seq}"));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&candidate) {
            Ok(()) => return Ok(TempStoreGuard { path: candidate }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "cannot create temporary verify directory {}: {e}",
                    candidate.display()
                ));
            }
        }
    }
    Err("cannot allocate unique temporary verify directory".into())
}

fn validate_store_paths(store_dir: &Path) -> Result<(), String> {
    let dir_meta = std::fs::symlink_metadata(store_dir)
        .map_err(|e| format!("cannot stat store dir {}: {e}", store_dir.display()))?;
    if dir_meta.file_type().is_symlink() {
        return Err(format!(
            "refusing symlinked store directory: {}",
            store_dir.display()
        ));
    }
    if !dir_meta.is_dir() {
        return Err(format!(
            "store path is not a directory: {}",
            store_dir.display()
        ));
    }
    let db_path = store_dir.join("db");
    let db_meta = std::fs::symlink_metadata(&db_path).map_err(|_| {
        format!(
            "not a stellereum store (no `db` file in {}): refusing to open",
            store_dir.display()
        )
    })?;
    if db_meta.file_type().is_symlink() {
        return Err(format!(
            "refusing symlinked store `db` file: {}",
            db_path.display()
        ));
    }
    if !db_meta.is_file() {
        return Err(format!(
            "not a stellereum store (`db` is not a regular file in {})",
            store_dir.display()
        ));
    }
    let blobs_path = store_dir.join("blobs");
    match std::fs::symlink_metadata(&blobs_path) {
        Ok(blobs_meta) => {
            if blobs_meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing symlinked store `blobs` entry: {}",
                    blobs_path.display()
                ));
            }
            if !blobs_meta.is_dir() {
                return Err(format!(
                    "not a stellereum store (`blobs` is not a directory in {})",
                    store_dir.display()
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "cannot stat store `blobs` in {}: {e}",
                store_dir.display()
            ));
        }
    }
    Ok(())
}

fn check_node_locks(store_dir: &Path) -> Result<Vec<File>, String> {
    let mut candidates = vec![store_dir.join(".node.lock")];
    if let Some(parent) = store_dir.parent() {
        if parent.as_os_str().is_empty() {
            candidates.push(Path::new(".").join(".node.lock"));
        } else {
            candidates.push(parent.join(".node.lock"));
        }
    } else if store_dir == Path::new(".") {
        candidates.push(Path::new("..").join(".node.lock"));
    }

    let mut guards = Vec::new();
    for lock_path in candidates {
        match std::fs::symlink_metadata(&lock_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "refusing symlinked node lock: {}",
                        lock_path.display()
                    ));
                }
                if !meta.is_file() {
                    return Err(format!(
                        "node lock is not a regular file: {}",
                        lock_path.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "cannot stat node lock {}: {e}",
                    lock_path.display()
                ));
            }
        }
        let file = File::open(&lock_path)
            .map_err(|e| format!("cannot open node lock {}: {e}", lock_path.display()))?;
        match file.try_lock() {
            Ok(()) => guards.push(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "refusing to verify store: node lock {} is actively held by another process",
                    lock_path.display()
                ));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!(
                    "cannot check node lock {}: {e}",
                    lock_path.display()
                ));
            }
        }
    }
    Ok(guards)
}

fn copy_store_for_readonly_verify(src: &Path, dst: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(src)
        .map_err(|e| format!("cannot read store directory {}: {e}", src.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|e| format!("cannot read store directory entry {}: {e}", src.display()))?;
        let name = entry.file_name();
        if name == ".node.lock" {
            continue;
        }
        let src_path = entry.path();
        let meta = std::fs::symlink_metadata(&src_path)
            .map_err(|e| format!("cannot stat store entry {}: {e}", src_path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing symlinked store entry: {}",
                src_path.display()
            ));
        }
        let dst_path = dst.join(&name);
        if meta.is_file() {
            std::fs::copy(&src_path, &dst_path).map_err(|e| {
                format!(
                    "cannot copy store file {} to temporary store: {e}",
                    src_path.display()
                )
            })?;
        } else if meta.is_dir() && name == "blobs" {
            std::fs::create_dir(&dst_path).map_err(|e| {
                format!(
                    "cannot create temporary blobs directory {}: {e}",
                    dst_path.display()
                )
            })?;
            let blob_entries = std::fs::read_dir(&src_path)
                .map_err(|e| format!("cannot read blobs directory {}: {e}", src_path.display()))?;
            for blob_entry in blob_entries {
                let blob_entry = blob_entry.map_err(|e| {
                    format!(
                        "cannot read blobs directory entry {}: {e}",
                        src_path.display()
                    )
                })?;
                let blob_src = blob_entry.path();
                let blob_meta = std::fs::symlink_metadata(&blob_src)
                    .map_err(|e| format!("cannot stat blob entry {}: {e}", blob_src.display()))?;
                if blob_meta.file_type().is_symlink() {
                    return Err(format!(
                        "refusing symlinked blob entry: {}",
                        blob_src.display()
                    ));
                }
                if !blob_meta.is_file() {
                    return Err(format!(
                        "unexpected non-regular entry in blobs directory: {}",
                        blob_src.display()
                    ));
                }
                let blob_dst = dst_path.join(blob_entry.file_name());
                std::fs::copy(&blob_src, &blob_dst).map_err(|e| {
                    format!(
                        "cannot copy blob file {} to temporary store: {e}",
                        blob_src.display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn verify_retained_header_prefix(
    storage: &Storage,
    start_height: u64,
    mut expected_hash: BlockHash,
    expected_shard: Option<u32>,
    min_verified_header_height: &mut Option<u64>,
    verified_header_count: &mut u64,
) -> Result<(), String> {
    let mut h = start_height;
    loop {
        let indexed = storage
            .hashes_at_height(h)
            .map_err(|e| format!("height {h}: cannot read height index: {e}"))?;
        if !indexed.is_empty() {
            if !indexed.contains(&expected_hash) {
                return Err(format!(
                    "height {h}: broken prev_hash link; child expects {} while height index holds {}",
                    hex::encode(expected_hash),
                    hex::encode(indexed[0])
                ));
            }
            if storage
                .get_block(&expected_hash)
                .map_err(|e| {
                    format!(
                        "height {h}: cannot read block {}: {e}",
                        hex::encode(expected_hash)
                    )
                })?
                .is_none()
            {
                return Err(format!(
                    "height {h}: broken prev_hash link; child expects {} which is absent while height index holds {}",
                    hex::encode(expected_hash),
                    hex::encode(indexed[0])
                ));
            }
            return Err(format!(
                "height {h}: non-contiguous block body retention gap above height {h}"
            ));
        }

        let hdr_opt = storage
            .header_at(h)
            .map_err(|e| format!("height {h}: cannot read header: {e}"))?;
        let hdr2_opt = storage
            .header_v2_at(h)
            .map_err(|e| format!("height {h}: cannot read header_v2: {e}"))?;

        if let Some(hdr) = &hdr_opt {
            if hdr.height != h {
                return Err(format!(
                    "height {h}: stored header reports height {}",
                    hdr.height
                ));
            }
            if hdr.block_hash != expected_hash {
                return Err(format!(
                    "height {h}: broken prev_hash link; child expects {}, header records {}",
                    hex::encode(expected_hash),
                    hex::encode(hdr.block_hash)
                ));
            }
        }

        if let Some(hdr2) = &hdr2_opt {
            if hdr2.header.height != h {
                return Err(format!(
                    "height {h}: stored header_v2 reports height {}",
                    hdr2.header.height
                ));
            }
            if hdr2.block_hash != expected_hash {
                return Err(format!(
                    "height {h}: broken prev_hash link; child expects {}, header_v2 records {}",
                    hex::encode(expected_hash),
                    hex::encode(hdr2.block_hash)
                ));
            }
            if let Some(shard) = expected_shard {
                if hdr2.header.shard_id != shard {
                    return Err(format!(
                        "height {h}: header_v2 shard mismatch (expected {shard}, got {})",
                        hdr2.header.shard_id
                    ));
                }
            }
        }

        if let (Some(hdr), Some(hdr2)) = (&hdr_opt, &hdr2_opt) {
            if hdr.height != hdr2.header.height
                || hdr.prev_hash != hdr2.header.prev_hash
                || hdr.state_root != hdr2.header.state_root
                || hdr.proposer != hdr2.header.proposer
                || hdr.timestamp != hdr2.header.timestamp
                || hdr.tx_count != hdr2.tx_count
                || hdr.gas_used != hdr2.gas_used
                || hdr.block_hash != hdr2.block_hash
            {
                return Err(format!(
                    "height {h}: header and header_v2 records are inconsistent"
                ));
            }
        }

        let next_prev_hash = match (&hdr2_opt, &hdr_opt) {
            (Some(hdr2), _) => hdr2.header.prev_hash,
            (None, Some(hdr)) => hdr.prev_hash,
            (None, None) => break,
        };

        *min_verified_header_height = Some(h);
        *verified_header_count += 1;
        if h == 0 {
            break;
        }
        expected_hash = next_prev_hash;
        h -= 1;
    }
    Ok(())
}

struct StoreVerifySummary {
    verified_count: u64,
    min_verified_height: u64,
    finalized_height: u64,
    finalized_hash: BlockHash,
    tip_shard: u32,
    verified_header_count: u64,
    min_verified_header_height: Option<u64>,
}

fn verify_opened_storage(storage: &Storage, chain_id: u64) -> Result<StoreVerifySummary, String> {
    let (finalized_height, finalized_hash) = storage
        .finalized()
        .map_err(|e| format!("cannot read finalized pointer: {e}"))?
        .ok_or_else(|| "store has no finalized pointer".to_string())?;

    let mut expected_hash: BlockHash = finalized_hash;
    let mut expected_shard: Option<u32> = None;
    let mut min_verified_height = finalized_height;
    let mut verified_count = 0u64;
    let mut min_verified_header_height: Option<u64> = None;
    let mut verified_header_count = 0u64;
    let mut h = finalized_height;

    loop {
        let block_opt = storage.get_block(&expected_hash).map_err(|e| {
            format!(
                "height {h}: cannot read block {}: {e}",
                hex::encode(expected_hash)
            )
        })?;
        let Some(block) = block_opt else {
            if h == finalized_height {
                return Err(format!(
                    "finalized tip block {} at height {h} is missing from store",
                    hex::encode(expected_hash)
                ));
            }
            verify_retained_header_prefix(
                storage,
                h,
                expected_hash,
                expected_shard,
                &mut min_verified_header_height,
                &mut verified_header_count,
            )?;
            break;
        };

        if block.height != h {
            return Err(format!(
                "height {h}: stored block reports height {}",
                block.height
            ));
        }
        match expected_shard {
            None => expected_shard = Some(block.shard_id),
            Some(shard) if block.shard_id != shard => {
                return Err(format!(
                    "height {h}: shard mismatch (expected {shard}, got {})",
                    block.shard_id
                ));
            }
            Some(_) => {}
        }

        let computed = block.compute_hash();
        if computed != expected_hash {
            return Err(format!(
                "height {h}: block hash mismatch for chain id {chain_id} (expected {}, computed {})",
                hex::encode(expected_hash),
                hex::encode(computed)
            ));
        }

        let indexed = storage
            .hashes_at_height(h)
            .map_err(|e| format!("height {h}: cannot read height index: {e}"))?;
        if !indexed.is_empty() && !indexed.contains(&expected_hash) {
            return Err(format!(
                "height {h}: block {} is missing from by_height index",
                hex::encode(expected_hash)
            ));
        }

        let tx_count = u32::try_from(block.transactions.len())
            .map_err(|_| format!("height {h}: transaction count exceeds u32::MAX"))?;

        if let Some(hdr) = storage
            .header_at(h)
            .map_err(|e| format!("height {h}: cannot read header: {e}"))?
        {
            if hdr.height != block.height
                || hdr.prev_hash != block.prev_hash
                || hdr.state_root != block.state_root
                || hdr.proposer != block.proposer
                || hdr.timestamp != block.timestamp
                || hdr.tx_count != tx_count
                || hdr.block_hash != computed
            {
                return Err(format!(
                    "height {h}: header record is inconsistent with block body"
                ));
            }
        }

        if let Some(hdr2) = storage
            .header_v2_at(h)
            .map_err(|e| format!("height {h}: cannot verify header_v2: {e}"))?
        {
            if hdr2.header != block.header()
                || hdr2.block_hash != computed
                || hdr2.tx_count != tx_count
            {
                return Err(format!(
                    "height {h}: header_v2 record is inconsistent with block body"
                ));
            }
        }

        if let Some(qc) = &block.precommit_qc {
            if qc.kind != VoteKind::Precommit
                || qc.height != block.height
                || qc.shard_id != block.shard_id
                || qc.block_hash != Some(computed)
            {
                return Err(format!(
                    "height {h}: precommit_qc is inconsistent with block"
                ));
            }
        }
        if let Some(last_qc) = &block.last_qc {
            let parent_h = block
                .height
                .checked_sub(1)
                .ok_or_else(|| format!("height {h}: genesis block must not carry last_qc"))?;
            if last_qc.kind != VoteKind::Precommit
                || last_qc.height != parent_h
                || last_qc.shard_id != block.shard_id
                || last_qc.block_hash != Some(block.prev_hash)
            {
                return Err(format!(
                    "height {h}: last_qc is inconsistent with parent block"
                ));
            }
        }

        min_verified_height = h;
        verified_count += 1;
        if h == 0 {
            break;
        }
        expected_hash = block.prev_hash;
        h -= 1;
    }

    let tip_shard = expected_shard.ok_or_else(|| "no blocks verified".to_string())?;
    Ok(StoreVerifySummary {
        verified_count,
        min_verified_height,
        finalized_height,
        finalized_hash,
        tip_shard,
        verified_header_count,
        min_verified_header_height,
    })
}

fn verify_store(store_dir: &Path, chain_id: &str, in_place: bool) -> Result<(), String> {
    let chain_id = parse_chain_id(chain_id)?;
    validate_store_paths(store_dir)?;
    let _lock_guards = check_node_locks(store_dir)?;

    // The CLI process is single-threaded and computes no consensus hash
    // before setting the node's one-time chain-id source.
    std::env::set_var("STELL_CHAIN_ID", chain_id.to_string());
    let effective_chain_id = consensus_chain_id();
    if effective_chain_id != chain_id {
        return Err(format!(
            "chain-id mismatch: requested {chain_id}, process frozen at {effective_chain_id}"
        ));
    }

    let _temp_guard = if in_place {
        None
    } else {
        let guard = create_temp_store_dir()?;
        copy_store_for_readonly_verify(store_dir, &guard.path)?;
        Some(guard)
    };
    let open_dir = _temp_guard
        .as_ref()
        .map_or(store_dir, |guard| guard.path.as_path());

    let summary = {
        let storage = Storage::open(open_dir)
            .map_err(|e| format!("cannot open store {}: {e}", store_dir.display()))?;
        verify_opened_storage(&storage, chain_id)?
    };

    println!(
        "verified store: {} block(s), heights {}..={}, shard {}, chain id {}",
        summary.verified_count,
        summary.min_verified_height,
        summary.finalized_height,
        summary.tip_shard,
        chain_id
    );
    if let Some(min_hdr_h) = summary.min_verified_header_height {
        println!(
            "verified retained prefix headers: {} header(s), heights {}..={}",
            summary.verified_header_count,
            min_hdr_h,
            summary.min_verified_height.saturating_sub(1)
        );
    }
    println!("finalized height: {}", summary.finalized_height);
    println!("finalized hash: {}", hex::encode(summary.finalized_hash));
    println!("checked: finalized pointer, contiguous retained block hashes, retained prefix header linkage, prev_hash linkage, chain-id binding, and header/QC consistency where present");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum::sharding::MASTERCHAIN_SHARD;

    fn fixture() -> Block {
        Block {
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
        }
    }

    #[test]
    fn current_stored_block_roundtrip_and_hash() {
        let block = fixture();
        let bytes = bincode::serialize(&block).unwrap();
        let decoded = decode_block(&bytes).unwrap();
        assert_eq!(decoded.height, 42);
        assert_eq!(decoded.compute_hash(), block.compute_hash());
    }

    #[test]
    fn corrupted_or_trailing_fixture_is_rejected() {
        let bytes = bincode::serialize(&fixture()).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_block(&bytes[..end]).is_err(), "truncated at {end}");
        }
        for suffix in [&[0][..], &[1, 2, 3][..]] {
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(suffix);
            assert!(decode_block(&trailing).is_err());
        }
    }

    #[test]
    fn forged_collection_length_is_rejected() {
        // shard_id (u32), height (u64), prev_hash and state_root precede
        // the fixed-width u64 transaction count in the current bincode format.
        let mut bytes = bincode::serialize(&fixture()).unwrap();
        let offset = 4 + 8 + 32 + 32;
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_block(&bytes).is_err());
    }

    #[test]
    fn changed_committed_field_does_not_match() {
        let block = fixture();
        let expected = block.compute_hash();
        assert!(check_hash(expected, expected).is_ok());
        let mut changed = block;
        changed.height += 1;
        let decoded = decode_block(&bincode::serialize(&changed).unwrap()).unwrap();
        assert!(check_hash(decoded.compute_hash(), expected).is_err());
    }

    #[test]
    fn signatures_are_not_covered_by_block_hash() {
        let mut block = fixture();
        let hash = block.compute_hash();
        block.validator_signatures.push(([7; 32], vec![8; 64]));
        let decoded = decode_block(&bincode::serialize(&block).unwrap()).unwrap();
        assert!(check_hash(decoded.compute_hash(), hash).is_ok());
    }

    #[test]
    fn hash_input_is_exactly_32_bytes_of_hex() {
        assert_eq!(expected_hash(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        for invalid in [
            "".to_string(),
            "0".repeat(63),
            "0".repeat(65),
            "z".repeat(64),
        ] {
            assert!(expected_hash(&invalid).is_err());
        }
    }

    #[test]
    fn oversized_input_is_rejected_before_decoding() {
        let bytes = vec![0; MAX_BLOCK_BYTES as usize + 1];
        assert_eq!(
            decode_block(&bytes).unwrap_err(),
            "block exceeds 32 MiB limit"
        );
    }

    #[test]
    fn reader_rejects_more_than_limit_even_without_file_metadata() {
        let reader = std::io::repeat(0).take(MAX_BLOCK_BYTES + 1);
        assert_eq!(
            read_bounded(reader).unwrap_err(),
            "block exceeds 32 MiB limit"
        );
    }

    #[test]
    fn unsafe_and_invalid_commands_refuse() {
        for args in [
            vec!["repair".to_string()],
            vec!["export".to_string()],
            vec![
                "verify-block".to_string(),
                "unused".into(),
                "1".into(),
                "abcd".into(),
            ],
            vec!["inspect-block".to_string(), ".".into(), "1".into()],
            vec!["inspect-block".to_string(), "unused".into(), "0".into()],
            vec!["verify-store".to_string()],
            vec!["verify-store".to_string(), ".".into(), "1".into()],
            vec!["verify-store".to_string(), "unused".into(), "0".into()],
        ] {
            assert!(run(&args).is_err());
        }
    }
}
