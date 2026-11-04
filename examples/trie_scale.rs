//! Scaling benchmark: prove sparse-tree insert cost is roughly independent of size.
use std::time::Instant;
use stellereum::cell::PatriciaTrie;
fn main() {
    for &n in &[100u64, 1_000, 10_000, 50_000] {
        let mut t = PatriciaTrie::new();
        let t0 = Instant::now();
        for i in 0..n {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_be_bytes());
            t.insert(&k, &i.to_be_bytes());
        }
        let build = t0.elapsed().as_secs_f64();
        // measure 1000 updates (existing or new) on the big trie
        let t1 = Instant::now();
        for i in 0..1000u64 {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(n + i).to_be_bytes());
            t.insert(&k, &i.to_be_bytes());
        }
        let upd = t1.elapsed().as_secs_f64();
        println!(
            "n={:>6}  build={:>7.1}/s  insert-on-large={:>8.0}/s",
            n,
            n as f64 / build,
            1000.0 / upd
        );
    }
}
