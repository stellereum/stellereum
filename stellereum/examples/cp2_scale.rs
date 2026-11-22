use std::time::Instant;
use stellereum::cell::PatriciaTrie;
use stellereum::cpat2::CompressedTrie;
fn main() {
    for &n in &[1_000u64, 10_000, 50_000] {
        // compressed
        let mut c = CompressedTrie::new();
        let t0 = Instant::now();
        for i in 0..n {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_be_bytes());
            c.insert(&k, &i.to_be_bytes());
        }
        let cb = t0.elapsed().as_secs_f64();
        // sparse (current prod)
        let mut s = PatriciaTrie::new();
        let t1 = Instant::now();
        for i in 0..n {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_be_bytes());
            s.insert(&k, &i.to_be_bytes());
        }
        let sb = t1.elapsed().as_secs_f64();
        println!(
            "n={:>6}  compressed={:>8.0} ins/s   sparse={:>8.0} ins/s",
            n,
            n as f64 / cb,
            n as f64 / sb
        );
    }
}
