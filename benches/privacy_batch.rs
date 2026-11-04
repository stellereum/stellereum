//! §9 MSM batch benchmarks (std-only; the repo carries no criterion dep).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench privacy_batch -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][privacy_batch]`
//! lines with ns/op for scalar vs batched verification at realistic sizes
//! (1/8/64 items). These are REPORTS, not gates: there are no timing asserts,
//! only correctness asserts — a slow machine must still be green.
//!
//! What is measured, and why it is honest:
//! * openings — `PedersenCommitment::verify` loop vs `batch_verify` (thin
//!   API; no MSM possible here without giving up determinism, so expect ~1x);
//! * conservation — per-transfer `verify_balance_conservation` loop vs
//!   `batch_verify_balance_conservation` (signed MSM per transfer);
//! * range proofs — `RangeProof::verify` loop vs `RangeProof::batch_verify`
//!   (per-bit OR checks stay scalar; the `2^i*C_i` reconstruction is MSM).

use curve25519_dalek::scalar::Scalar;
use std::time::Instant;
use stellereum::crypto_privacy::{
    msm_backend_name, BitProof, ConfidentialTransfer, PedersenCommitment, RangeProof,
};

fn medal(nanos: f64) -> String {
    if nanos >= 1_000_000.0 {
        format!("{:.3} ms/op", nanos / 1_000_000.0)
    } else if nanos >= 1_000.0 {
        format!("{:.3} us/op", nanos / 1_000.0)
    } else {
        format!("{:.1} ns/op", nanos)
    }
}

/// Median-of-repeats timing of `f`, reported as ns per `per_op` units.
fn time_ns_per_op(per_op: usize, repeats: usize, warmup: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..warmup {
        f();
    }
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos() as f64 / per_op as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn report(item: &str, size: usize, scalar_ns: f64, batch_ns: f64) {
    println!(
        "[bench][privacy_batch][{}] n={size:>3} backend={} scalar={} batch={} speedup={:.2}x",
        item,
        msm_backend_name(),
        medal(scalar_ns),
        medal(batch_ns),
        scalar_ns / batch_ns.max(1e-9),
    );
}

fn openings(n: usize) -> Vec<(PedersenCommitment, u64, Scalar)> {
    (0..n)
        .map(|i| {
            let v = 1_000 + (i as u64) * 37;
            let r = Scalar::from(0x5EED_u64 + i as u64);
            (PedersenCommitment::commit(v, &r), v, r)
        })
        .collect()
}

fn transfers(n: usize) -> Vec<ConfidentialTransfer> {
    (0..n)
        .map(|i| {
            let r = Scalar::from(0x5EED_u64 + i as u64);
            let c_in = PedersenCommitment::commit(1_480, &r);
            let c_out = PedersenCommitment::commit(1_460, &r);
            ConfidentialTransfer::new(vec![c_in], vec![c_out], 20)
        })
        .collect()
}

fn ranged(n: usize, bits: u8) -> Vec<(PedersenCommitment, RangeProof)> {
    (0..n)
        .map(|i| {
            let v = 1_000 + (i as u64) * 37;
            let r = Scalar::from(0xBEEF_u64 + i as u64);
            let c = PedersenCommitment::commit(v, &r);
            let p = RangeProof::prove(&c, v, &r, bits);
            (c, p)
        })
        .collect()
}

#[test]
fn bench_openings_scalar_vs_batch() {
    for &n in &[1usize, 8, 64] {
        let ops = openings(n);
        let scalar = time_ns_per_op(n, 20, 2, || {
            let got: Vec<bool> = ops.iter().map(|(c, v, r)| c.verify(*v, r)).collect();
            assert!(got.iter().all(|&b| b));
        });
        let batch = time_ns_per_op(n, 20, 2, || {
            let got = PedersenCommitment::batch_verify(&ops);
            assert!(got.iter().all(|&b| b));
        });
        report("openings", n, scalar, batch);
    }
}

#[test]
fn bench_conservation_scalar_vs_batch() {
    for &n in &[1usize, 8, 64] {
        let txs = transfers(n);
        let scalar = time_ns_per_op(n, 20, 2, || {
            let got: Vec<bool> = txs
                .iter()
                .map(|t| t.verify_balance_conservation())
                .collect();
            assert!(got.iter().all(|&b| b));
        });
        let batch = time_ns_per_op(n, 20, 2, || {
            let got = ConfidentialTransfer::batch_verify_balance_conservation(&txs);
            assert!(got.iter().all(|&b| b));
        });
        report("conservation", n, scalar, batch);
    }
}

#[test]
fn bench_range_scalar_vs_batch() {
    // (batch size, range bits, repeats): proving cost is setup-only, but keep
    // the 64-batch at 16 bits so debug-profile runs stay usable; the
    // scalar-vs-batch comparison inside each row is still apples-to-apples.
    for &(n, bits, repeats) in &[(1usize, 32u8, 30usize), (8, 32, 10), (64, 16, 5)] {
        let pairs = ranged(n, bits);
        assert!(pairs.iter().all(|(c, p)| RangeProof::verify(c, p)));
        let refs: Vec<(&PedersenCommitment, &RangeProof)> =
            pairs.iter().map(|(c, p)| (c, p)).collect();
        let scalar = time_ns_per_op(n, repeats, 1, || {
            let got: Vec<bool> = refs.iter().map(|(c, p)| RangeProof::verify(c, p)).collect();
            assert!(got.iter().all(|&b| b));
        });
        let batch = time_ns_per_op(n, repeats, 1, || {
            let got = RangeProof::batch_verify(&refs);
            assert!(got.iter().all(|&b| b));
        });
        report(&format!("range{bits}"), n, scalar, batch);
    }
}

/// Absolute win evidence: the scalar reference twin vs the shipped MSM
/// `BitProof::verify`, over 64 bit-proofs. Unlike the rows above (which pin
/// scalar==batch parity), this row is expected to show the MSM clearly
/// faster — it is the throughput this §9 item ships.
#[test]
fn bench_bitproof_reference_vs_msm() {
    let n = 64usize;
    let items: Vec<(PedersenCommitment, BitProof)> = (0..n)
        .map(|i| {
            let bit = i % 2 == 0;
            let r = Scalar::from(0xB17_u64 + i as u64);
            let c = PedersenCommitment::commit(bit as u64, &r);
            let p = BitProof::prove(&c, bit, &r);
            (c, p)
        })
        .collect();
    assert!(items.iter().all(|(c, p)| BitProof::verify(c, p)));
    assert!(items.iter().all(|(c, p)| BitProof::verify_scalar(c, p)));
    let reference = time_ns_per_op(n, 20, 2, || {
        let got: Vec<bool> = items
            .iter()
            .map(|(c, p)| BitProof::verify_scalar(c, p))
            .collect();
        assert!(got.iter().all(|&b| b));
    });
    let msm = time_ns_per_op(n, 20, 2, || {
        let got: Vec<bool> = items.iter().map(|(c, p)| BitProof::verify(c, p)).collect();
        assert!(got.iter().all(|&b| b));
    });
    report("bitproof-ref-vs-msm", n, reference, msm);
}
