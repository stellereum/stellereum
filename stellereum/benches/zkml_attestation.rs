//! zkML ATTESTATION benchmarks (std-only; the repo carries no criterion dep).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench zkml_attestation -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][zkml_attestation]`
//! lines with forge/verify times and proof sizes.
//!
//! NOTE (honesty rewrite): the previous version of this bench measured the
//! removed Groth16-like `stellereum::snark` API (`setup_test_only`,
//! `prove_inference`, `verify_snark_proof`). That API no longer exists: the
//! chain's zkML path is ATTESTATION (re-execution bound to a model spec via a
//! BLAKE3 trace root + Fiat-Shamir), NOT a zero-knowledge proof. See
//! `stell_zkmlCapabilities` (`zero_knowledge:false`). This bench now measures
//! the real path: `ZkMlProof::forge_structural_proof` + `verify_inference`.
//!
//! These are REPORTS, not gates: there are no timing asserts, only
//! correctness asserts (every forge must verify) - a slow machine must still
//! be green.

use std::time::Instant;
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, ZkMlProof};

fn ref_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
}

fn time_ms(reps: u32, f: impl Fn()) -> f64 {
    // Warmup, then the timed reps.
    f();
    let t0 = Instant::now();
    for _ in 0..reps {
        f();
    }
    t0.elapsed().as_secs_f64() * 1000.0 / reps as f64
}

#[test]
fn ref_model_attestation() {
    let m = ref_model();
    assert!(m.is_attestation_compatible());
    // Reference model ([3,4] -> [11,7]).
    let proof = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[11, 7]);
    assert!(proof.verify_inference());

    let forge_ms = time_ms(10, || {
        let p = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[11, 7]);
        assert!(p.verify_inference());
    });
    let verify_ms = time_ms(50, || {
        assert!(proof.verify_inference());
    });

    println!(
        "[bench][zkml_attestation][ref_model] forge={forge_ms:.3}ms \
         verify={verify_ms:.3}ms proof_bytes={}",
        proof.proof_bytes.len(),
    );
}

#[test]
fn verify_scaling_public_inputs() {
    // 1-wide vs 8-wide single layer: attestation verify cost grows with the
    // trace size. This row justifies the per-input gas arm.
    for width in [1usize, 8] {
        let m = QuantizedLinearModel::new(vec![QuantizedLayer::new(
            width,
            width,
            vec![1; width * width],
            vec![0; width],
        )]);
        assert!(m.is_attestation_compatible());
        let inputs = vec![2u64; width];
        let outputs = vec![2 * width as u64; width];
        let proof = ZkMlProof::forge_structural_proof(&m, &inputs, &outputs);
        assert!(proof.verify_inference());
        let verify_ms = time_ms(20, || {
            assert!(proof.verify_inference());
        });
        println!(
            "[bench][zkml_attestation][verify_scaling] width={width} n_public={} \
             verify={verify_ms:.3}ms proof_bytes={}",
            inputs.len(),
            proof.proof_bytes.len(),
        );
    }
}

#[test]
fn forge_scaling_layers() {
    // 1 vs 2 layers: forge cost grows with the model size, verify stays
    // roughly flat (trace-root check + re-execution).
    let one = ref_model();
    let two = QuantizedLinearModel::new(vec![
        QuantizedLayer::new(1, 1, vec![0], vec![7]),
        QuantizedLayer::new(1, 1, vec![3], vec![-2]),
    ]);
    assert!(two.is_attestation_compatible());
    // one: [3,4] -> [11,7]; two: [10] -> layer1([10]) = [7], layer2([7]) = [3*7-2] = [19].
    for (tag, m, inputs, outputs) in [
        ("1layer", one, vec![3u64, 4], vec![11u64, 7]),
        ("2layer", two, vec![10u64], vec![19u64]),
    ] {
        let forge_ms = time_ms(10, || {
            let p = ZkMlProof::forge_structural_proof(&m, &inputs, &outputs);
            assert!(p.verify_inference());
        });
        println!("[bench][zkml_attestation][forge_scaling] {tag} forge+verify={forge_ms:.3}ms");
    }
}
