//! Ops tool: inspect (and, with `--demote`, surgically demote) the staking
//! ledger inside a node's latest domains snapshot.
//!
//! WHY THIS EXISTS: if a bonded validator's key is lost while its power is
//! required for quorum, the chain halts and no on-chain transaction can fix
//! it (every fix needs finality). Demoting the lost key's self-bond below
//! `MIN_VALIDATOR_BOND` drops it from `to_validator_set` while moving no
//! coins: the bond stays locked, the set shrinks deterministically, and the
//! remaining validators regain quorum with byte-identical state on every
//! node they run this against (same input snapshot -> same output bytes).
//!
//! RULES: stop ALL nodes first. Run inspect on every node, verify the latest
//! paired snapshot height AND bytes are identical, then demote on every node,
//! then re-inspect. If heights differ, do NOT demote: resolve to a common
//! snapshot first (prune newer on the ahead node) or you will fork.
//!
//! Usage:
//!   ledger_tool <store-dir>                       # inspect only
//!   ledger_tool <store-dir> --demote <validator-hex>
//!   ledger_tool <store-dir> --rollback <height>   # rewind above height

use std::collections::BTreeMap;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: ledger_tool <store-dir> [--demote <validator-hex>]");
        std::process::exit(2);
    }
    let dir = std::path::Path::new(&args[1]);
    if args.len() > 3 && args[2] == "--rollback" {
        let height: u64 = args[3].parse().expect("numeric height");
        return rollback(dir, height);
    }
    let demote: Option<[u8; 32]> = if args.len() > 3 && args[2] == "--demote" {
        let b = hex::decode(&args[3]).expect("hex validator id");
        Some(b.try_into().expect("32 bytes"))
    } else {
        None
    };

    let storage = stellereum::storage::Storage::open(dir).expect("open store");
    let domains_res = storage.latest_domains().expect("read latest domains");
    let (height, bytes) = match domains_res {
        Some((h, b)) => (h, b),
        None => {
            if demote.is_some() {
                panic!("no domains snapshot found");
            }
            println!("no domains snapshot found");
            println!("pq_keys entries: {}", storage.pq_keys.len());
            return;
        }
    };
    println!("latest domains snapshot height: {height}");
    println!(
        "snapshot bytes sha256: {}",
        hex::encode(blake3::hash(&bytes).as_bytes())
    );

    let snap: stellereum::storage::DomainSnapshot =
        stellereum::storage::decode_domain_snapshot(&bytes).expect("decode DomainSnapshot");
    println!("validators:");
    let mut ids: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (id, v) in &snap.staking.validators {
        println!(
            "  {} self_bond={} delegated={} slashed={}",
            hex::encode(id),
            v.self_bond,
            v.delegated,
            v.total_slashed
        );
        ids.insert(*id, v.self_bond);
    }
    let set = snap.staking.to_validator_set();
    println!("to_validator_set members: {}", set.validators.len());
    println!("quorum power: {}", set.quorum_power());
    println!("pq_keys entries: {}", storage.pq_keys.len());

    if let Some(d) = demote {
        let v = snap
            .staking
            .validators
            .get(&d)
            .expect("validator not in ledger");
        println!("demoting {} (self_bond {})", hex::encode(d), v.self_bond);
        assert!(
            v.self_bond >= stellereum::staking::MIN_VALIDATOR_BOND,
            "already below minimum, nothing to do"
        );
        let mut snap = snap;
        let rec = snap.staking.validators.get_mut(&d).unwrap();
        // One nano below the minimum: drops out of the consensus set, moves
        // no coins, keeps every other number (delegations, rewards, slash
        // history) intact for a future top-up/repair.
        rec.self_bond = stellereum::staking::MIN_VALIDATOR_BOND - 1;
        let out = bincode::serialize(&snap).expect("re-encode");
        // Overwrite the SAME height: restore reads latest-paired, so the
        // edited snapshot is what every restarted node loads.
        storage.put_domains(height, &out).expect("write back");
        println!(
            "wrote demoted snapshot at height {height} ({} bytes)",
            out.len()
        );
        println!(
            "new bytes sha256: {}",
            hex::encode(blake3::hash(&out).as_bytes())
        );
    }
}

/// Rewind a store to `height`: delete every height-keyed entry above it,
/// prune receipts above it, and re-point the finalized pointer at it.
///
/// WHY: if history past H must be abandoned identically on two nodes (e.g. a
/// stake that broke quorum admitted after the last restorable snapshot),
/// both nodes pruned to the same H restore byte-identical state and resume
/// proposing H+1 together. RULES: stop ALL nodes first; H must exist in
/// `by_height` on EVERY node; verify post-run latest heights match; keep a
/// full data-dir backup (this deletes data, no undo besides the backup).
fn rollback(dir: &std::path::Path, height: u64) {
    let db = sled::open(dir).expect("open sled db");
    // 1. Anchor hash first (by_height itself gets pruned below). NOTE:
    // by_height keys are height(8B BE) + block_hash(32B), not bare heights.
    let by_height = db.open_tree("by_height").expect("by_height tree");
    let mut anchor: Option<[u8; 32]> = None;
    for kv in by_height.iter().flatten() {
        if kv.0.len() == 40 {
            let h = u64::from_be_bytes(kv.0[..8].try_into().unwrap());
            if h == height {
                anchor = Some(kv.0[8..].try_into().expect("32-byte hash"));
                break;
            }
        }
    }
    let anchor =
        anchor.unwrap_or_else(|| panic!("height {height} missing from by_height — refusing"));
    println!("anchor: height {height} hash {}", hex::encode(anchor));

    // 2. Height-keyed trees: drop every 8-byte-BE key above H. by_height
    // uses 40-byte height+hash keys: height is the first 8 bytes. Non-key
    // shapes (bare hashes, names) are left alone by construction. Bare
    // hash-keyed bodies (blocks tree) are content-addressed and self-
    // validating, so orphans above H are inert (no walk can anchor on them
    // once finality points at H) — left in place deliberately.
    // Address-keyed post-quantum public keys (pq_keys tree) are persistent
    // identity records and are gracefully preserved across rollback.
    let mut total = 0usize;
    for name in [
        "by_height",
        "state",
        "domains",
        "headers",
        "session_keys",
        "bridge",
        "confidential",
        "zkml_models",
        "cross_shard",
        "pq_keys",
    ] {
        let tree = db.open_tree(name).expect("open tree");
        let mut n = 0usize;
        let mut batch = Vec::new();
        for kv in tree.iter().flatten() {
            let h = if kv.0.len() == 8 {
                u64::from_be_bytes(kv.0.as_ref().try_into().unwrap())
            } else if kv.0.len() == 40 {
                u64::from_be_bytes(kv.0[..8].try_into().unwrap())
            } else {
                continue;
            };
            if h > height {
                batch.push(kv.0.to_vec());
                n += 1;
            }
        }
        for k in batch {
            tree.remove(k).expect("remove");
        }
        println!("tree {name}: removed {n} entries above {height}");
        total += n;
    }

    // 3. Receipts are tx-hash-keyed: deserialize and filter by inner height.
    let receipts = db.open_tree("receipts_v1").expect("receipts tree");
    let mut rn = 0usize;
    for kv in receipts.iter().flatten() {
        let keep = match stellereum::storage::decode_receipt(&kv.1) {
            Ok(r) => r.height <= height,
            Err(_) => true, // unknown shape: fail closed, keep it
        };
        if !keep {
            receipts.remove(&kv.0).expect("remove receipt");
            rn += 1;
        }
    }
    println!("tree receipts_v1: removed {rn} entries above {height}");

    // 4. Re-point finality at the anchor (both keys: height AND hash).
    let meta = db.open_tree("meta").expect("meta tree");
    meta.insert("finalized_height", &height.to_be_bytes())
        .expect("set height");
    meta.insert("finalized_hash", &anchor).expect("set hash");
    println!("meta finalized -> ({height}, {})", hex::encode(anchor));

    db.flush().expect("flush");
    println!("rollback complete: {total} height entries + {rn} receipts removed");
}
