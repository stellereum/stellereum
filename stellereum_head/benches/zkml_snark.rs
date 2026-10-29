//! §2 zkML SUCCINCT-half benchmarks (std-only; the repo carries no criterion dep).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench zkml_snark -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][zkml_snark]`
//! lines with setup/prove/verify times, the constraint count, and the
//! on-chain sizes (proof bytes, VK bytes).
//!
//! These are REPORTS, not gates: there are no timing asserts, only
//! correctness asserts (every prove must verify) - a slow machine must still
//! be green. Uses the deterministic TEST-ONLY setup (seeded); production
//! timing differs only in the setup phase (entropy + ceremony), not in
//! prove/verify.
//!
//! What is measured, and why it is honest:
//! * `ref_model_circuit` - constraint count + setup/prove/verify for the
//!   2x2 reference model ([3,4] -> [11,7]). The headline numbers for the
//!   succinct path: constant-size proof (192 B) and constant-time verify
//!   against linear re-execution.
//! * `verify_scaling_public_inputs` - verifier time as the public-input
//!   count grows (1-wide vs 8-wide single layer): Groth16 verify is 3
//!   pairings + O(#public) MSM, so this row justifies the per-public-input
//!   gas arm (`GAS_GROTH16_PER_PUBLIC_INPUT`).
//! * `prove_scaling_layers` - prover time for 1 vs 2 layers: proving is
//!   quasi-linear in constraints, so this row shows what depth costs the
//!   (off-chain) prover while on-chain verify stays flat.

use std::time::Instant;
use stellereum::snark::{
    prove_inference, setup_test_only, verify_snark_proof, QuantizedInferenceCircuit,
};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel};

const SEED: u64 = 0x534E41524B;

fn ref_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(2, 2, vec![2, -1, 1, 3], vec![1, -2])])
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
fn ref_model_circuit() {
    let m = ref_model();
    assert!(m.is_snark_compatible());
    let view = m.snark_view();
    let n = QuantizedInferenceCircuit::constraint_count_for(&view).expect("countable");

    let t0 = Instant::now();
    let (pk_bytes, vk) = setup_test_only(&view, SEED).expect("test setup works");
    let setup_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let (out, proof) =
        prove_inference(&view, m.compute_model_hash(), &[3, 4], &pk_bytes, vk.vk_hash)
            .expect("honest prove works");
    assert_eq!(out, vec![11, 7]);
    let prove_ms = time_ms(3, || {
        let _ = prove_inference(&view, m.compute_model_hash(), &[3, 4], &pk_bytes, vk.vk_hash)
            .expect("honest prove works");
    });
    let verify_ms = time_ms(10, || {
        assert!(verify_snark_proof(&vk.vk_bytes, &proof));
    });

    println!(
        "[bench][zkml_snark][ref_model] constraints={n} setup={setup_ms:.1}ms \
         prove={prove_ms:.1}ms verify={verify_ms:.3}ms proof_bytes={} vk_bytes={} pk_bytes={}",
        proof.proof_bytes.len(),
        vk.vk_bytes.len(),
        pk_bytes.len(),
    );
}

#[test]
fn verify_scaling_public_inputs() {
    // 1-wide vs 8-wide single layer: 2 vs 16 public inputs. Setup+prove once
    // per shape; verify is the timed row (the on-chain cost).
    for width in [1usize, 8] {
        let m = QuantizedLinearModel::new(vec![QuantizedLayer::new(
            width,
            width,
            vec![1; width * width],
            vec![0; width],
        )]);
        assert!(m.is_snark_compatible());
        let view = m.snark_view();
        let n = QuantizedInferenceCircuit::constraint_count_for(&view).expect("countable");
        let (pk_bytes, vk) = setup_test_only(&view, SEED + width as u64).expect("setup works");
        let inputs = vec![2i64; width];
        let (out, proof) =
            prove_inference(&view, m.compute_model_hash(), &inputs, &pk_bytes, vk.vk_hash)
                .expect("prove works");
        assert_eq!(out, vec![2 * width as i64; width]);
        let verify_ms = time_ms(10, || {
            assert!(verify_snark_proof(&vk.vk_bytes, &proof));
        });
        println!(
            "[bench][zkml_snark][verify_scaling] width={width} n_public={} constraints={n} \
             verify={verify_ms:.3}ms vk_bytes={}",
            vk.n_public_inputs,
            vk.vk_bytes.len(),
        );
    }
}

#[test]
fn prove_scaling_layers() {
    // 1 vs 2 layers (second layer identity-shaped through a bounded
    // activation so the worst-case gate still passes): prover scales with
    // constraints, verifier stays ~flat.
    let one = ref_model();
    let two = QuantizedLinearModel::new(vec![
        QuantizedLayer::new(1, 1, vec![0], vec![7]),
        QuantizedLayer::new(1, 1, vec![3], vec![-2]),
    ]);
    assert!(two.is_snark_compatible());
    for (tag, m, inputs) in [("1layer", one, vec![3, 4]), ("2layer", two, vec![10])] {
        let view = m.snark_view();
        let n = QuantizedInferenceCircuit::constraint_count_for(&view).expect("countable");
        let (pk_bytes, vk) = setup_test_only(&view, SEED).expect("setup works");
        let prove_ms = time_ms(3, || {
            let (_, proof) =
                prove_inference(&view, m.compute_model_hash(), &inputs, &pk_bytes, vk.vk_hash)
                    .expect("prove works");
            assert!(verify_snark_proof(&vk.vk_bytes, &proof));
        });
        println!("[bench][zkml_snark][prove_scaling] {tag} constraints={n} prove+verify={prove_ms:.1}ms");
    }
}
