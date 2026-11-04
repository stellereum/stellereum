//! Split / merge COST benchmark for the dynamic sharding path.
//!
//! Prints, for a synthetic account set of N accounts, the wall-clock cost of
//! the operations a real split/merge performs:
//!
//!   * the ACCOUNT re-assignment (the prefix rule),
//!   * the TRIE migration (every account leaf moved into a child trie),
//!   * the trie migration VERIFICATION,
//!   * the merge (the inverse).
//!
//! Usage:
//!   cargo run --release --example sharding_split_merge_bench
//!   cargo run --release --example sharding_split_merge_bench -- 1000 10000 100000
//!
//! HONESTY: this measures the IN-PROCESS state machine over a synthetic
//! account set. It does NOT measure a live-network split (none has been
//! performed) and it does NOT include the consensus cost of shipping the
//! migrated state between nodes — the migration is a local state operation
//! here.

use std::time::Instant;

use stellereum::cell::PatriciaTrie;
use stellereum::sharding::{
    MigrationManifest, ShardTopology, TrieMigration, SHARD_SPLIT_LOAD_THRESHOLD,
};

fn synthetic_address(i: u64) -> [u8; 32] {
    let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&z.to_be_bytes());
    a[8..16].copy_from_slice(&z.rotate_left(17).to_be_bytes());
    a
}

fn main() {
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse::<u64>().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![1_000u64, 10_000, 100_000]
    } else {
        sizes
    };

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║   DYNAMIC SHARDING — SPLIT / MERGE COST (synthetic account set)  ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!(
        "thresholds: split_load>={} merge_load<={} min_accounts=100 max_shards=16",
        SHARD_SPLIT_LOAD_THRESHOLD,
        stellereum::sharding::SHARD_MERGE_LOAD_THRESHOLD
    );
    println!(
        "NOTE: in-process state-machine cost only. No live-network split has been performed.\n"
    );
    println!(
        "{:>10}  {:>12}  {:>12}  {:>12}  {:>12}  {:>12}",
        "accounts", "build", "split", "migrate", "verify", "merge"
    );
    println!("{}", "-".repeat(76));

    for n in sizes {
        // ---- build the synthetic state -------------------------------------
        let t0 = Instant::now();
        let mut topology = ShardTopology::new();
        let mut trie = PatriciaTrie::new();
        let mut manifest = MigrationManifest::new();
        for i in 0..n {
            let addr = synthetic_address(i);
            let balance = 1_000 + (i % 977);
            topology.register_account(addr, balance);
            let mut leaf = Vec::with_capacity(16);
            leaf.extend_from_slice(&balance.to_be_bytes());
            leaf.extend_from_slice(&0u64.to_be_bytes());
            trie.insert(&addr, &leaf);
            manifest.own(addr, addr);
        }
        let build = t0.elapsed();

        // ---- split ----------------------------------------------------------
        topology.record_tx_load(1, SHARD_SPLIT_LOAD_THRESHOLD + 1);
        let t1 = Instant::now();
        let split = topology
            .check_and_split(1)
            .expect("the split trigger fires for this account count");
        let split_elapsed = t1.elapsed();

        // ---- trie migration -------------------------------------------------
        let migration = TrieMigration::new(split.plan.clone(), manifest.clone());
        let t2 = Instant::now();
        let (child0, child1) = migration.execute_split(&trie).expect("migration");
        let migrate = t2.elapsed();

        // ---- verification ---------------------------------------------------
        let t3 = Instant::now();
        migration
            .verify_split(&trie, &child0, &child1)
            .expect("verification");
        let verify = t3.elapsed();

        // ---- merge (the inverse) --------------------------------------------
        topology.decay_load(SHARD_SPLIT_LOAD_THRESHOLD + 1);
        let [c0, c1] = split.children;
        let t4 = Instant::now();
        let merge = topology
            .check_and_merge(c0.shard_id, c1.shard_id)
            .expect("the merge trigger fires once the load decayed");
        let merge_migration = TrieMigration::new(merge.plan.clone(), manifest.clone());
        let _ = merge_migration
            .execute_merge(&child0, &child1)
            .expect("merge");
        let merge_elapsed = t4.elapsed();

        println!(
            "{:>10}  {:>12}  {:>12}  {:>12}  {:>12}  {:>12}",
            n,
            fmt(build),
            fmt(split_elapsed),
            fmt(migrate),
            fmt(verify),
            fmt(merge_elapsed)
        );
    }
}

fn fmt(d: std::time::Duration) -> String {
    let us = d.as_micros();
    if us >= 1_000_000 {
        format!("{:.2}s", d.as_secs_f64())
    } else if us >= 1_000 {
        format!("{:.2}ms", d.as_secs_f64() * 1_000.0)
    } else {
        format!("{us}us")
    }
}
