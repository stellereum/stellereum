use bincode::Options;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use stellereum::sharding::Block;

const MAX_BLOCK_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CHAIN_BLOCKS: usize = 1024;
const USAGE: &str = "usage: stellereum-ledger-tool inspect-block <bincode-file> <chain-id>\n       stellereum-ledger-tool verify-block <bincode-file> <chain-id> <expected-hash-hex>\n       stellereum-ledger-tool verify-chain current-v1 <chain-id> <block-file> <block-file> [block-file...]\n       stellereum-ledger-tool repair|export [arguments...]\ncurrent-v1 means the full current node Block encoded by bincode fixed-int; legacy formats are not supported\ninput must be a stable, independent current-format block file, not a live store or a file being written; no snapshot or concurrency protection is provided\ninput limit: 32 MiB per block, 1024 blocks per chain; decoded heap and hash computation are not bounded by this limit; use OS resource limits for untrusted input";

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
    if !std::fs::metadata(path)
        .map_err(|e| format!("cannot stat input: {e}"))?
        .is_file()
    {
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
        ] {
            assert!(run(&args).is_err());
        }
    }
}
