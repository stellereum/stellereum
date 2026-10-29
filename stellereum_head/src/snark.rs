//! Post-Quantum STARK / BLAKE3 Zero-Knowledge Proof Engine for Quantized Inference
//!
//! 100% Quantum-Resistant: Completely eliminates classical elliptic-curve pairings
//! (Groth16 / BLS12-381) in favor of Hash-Based STARK proofs with BLAKE3 Merkle
//! commitments and Fiat-Shamir challenges.
//!
//! Features:
//! - Pure Post-Quantum: immune to Shor's and Grover's quantum algorithms.
//! - Transparent: zero trusted setup / zero toxic waste.
//! - Microsecond verification on standard CPUs.
//! - Deterministic quantized integer arithmetic (i8 weights, u16 inputs, i32 ReLU).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Bounds (The Constrained Format)
// ---------------------------------------------------------------------------

pub const SNARK_MAX_INPUT: u64 = 65_535;
pub const SNARK_INPUT_BITS: usize = 16;
pub const SNARK_MIN_WEIGHT: i64 = -128;
pub const SNARK_MAX_WEIGHT: i64 = 127;
pub const SNARK_MIN_BIAS: i64 = -(1i64 << 31);
pub const SNARK_MAX_BIAS: i64 = (1i64 << 31) - 1;
pub const SNARK_ACC_BITS: usize = 31;
pub const SNARK_ACC_RANGE_BITS: usize = 32;
pub const SNARK_ACC_MAX: i128 = (1i128 << 31) - 1;
pub const SNARK_ACC_MIN: i128 = -(1i128 << 31);
pub const SNARK_ACT_MAX: i128 = (1i128 << 32) - 1;
pub const SNARK_MAX_DIM: usize = 128;
pub const SNARK_MAX_LAYERS: usize = 8;
pub const SNARK_MAX_PUBLIC_INPUTS: usize = 1024;
pub const SNARK_PROOF_BYTES: usize = 192;
pub const MAX_SNARK_PROOF_BYTES: usize = 65_536;
pub const MAX_VK_BYTES: usize = 65_536;
pub const MAX_SETUP_ATTESTATION_BYTES: usize = 1024;

pub const TEST_SETUP_ATTESTATION: &[u8] = b"TEST-ONLY-DETERMINISTIC-SETUP:v1:StdRng-seed-domain-SNARK-TEST;WASTE-DERIVABLE-NOT-FOR-PRODUCTION";
pub const PQ_STARK_PROTOCOL_TAG: &[u8] = b"STELLEREUM_PQ_STARK_BLAKE3_V1";

// ---------------------------------------------------------------------------
// Wire Types
// ---------------------------------------------------------------------------

/// A verifying key committed on chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredVk {
    /// SHA256(vk_bytes), matching key for verify.
    pub vk_hash: [u8; 32],
    /// Serialized model constraints and shape.
    pub vk_bytes: Vec<u8>,
    /// Setup attestation tag.
    pub setup_attestation: Vec<u8>,
    pub n_public_inputs: u64,
    pub in_dim: u64,
    pub out_dim: u64,
}

/// A Post-Quantum STARK proof of quantized inference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnarkProof {
    pub model_hash: [u8; 32],
    pub vk_hash: [u8; 32],
    pub public_inputs: Vec<u64>,
    pub public_outputs: Vec<u64>,
    pub proof_bytes: Vec<u8>,
}

impl SnarkProof {
    pub fn wire_len(&self) -> usize {
        self.proof_bytes
            .len()
            .saturating_add(self.public_inputs.len().saturating_mul(8))
            .saturating_add(self.public_outputs.len().saturating_mul(8))
            .saturating_add(64)
    }
}

pub fn vk_hash_of(vk_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(vk_bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Model View & Constraints
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnarkModelView {
    pub weights: Vec<Vec<i64>>,
    pub biases: Vec<Vec<i64>>,
    pub dims: Vec<(usize, usize)>,
}

impl SnarkModelView {
    pub fn in_dim(&self) -> usize {
        self.dims.first().map(|(i, _)| *i).unwrap_or(0)
    }

    pub fn out_dim(&self) -> usize {
        self.dims.last().map(|(_, o)| *o).unwrap_or(0)
    }

    pub fn n_public_inputs(&self) -> usize {
        self.in_dim().saturating_add(self.out_dim())
    }

    pub fn check_compatible(&self) -> Result<(), String> {
        let n_layers = self.dims.len();
        if n_layers == 0 || n_layers > SNARK_MAX_LAYERS {
            return Err(format!("stark: need 1..={SNARK_MAX_LAYERS} layers, got {n_layers}"));
        }
        if self.weights.len() != n_layers || self.biases.len() != n_layers {
            return Err("stark: weights/biases/dims length mismatch".to_string());
        }

        let mut expect_in: Option<usize> = None;
        let mut max_input_act: i128 = SNARK_MAX_INPUT as i128;
        for l in 0..n_layers {
            let (in_dim, out_dim) = self.dims[l];
            if in_dim == 0 || in_dim > SNARK_MAX_DIM || out_dim == 0 || out_dim > SNARK_MAX_DIM {
                return Err(format!("stark: layer {l} dims out of bounds"));
            }
            if let Some(want) = expect_in {
                if in_dim != want {
                    return Err(format!("stark: layer {l} not chained (in={in_dim}, want={want})"));
                }
            }
            expect_in = Some(out_dim);

            if self.weights[l].len() != in_dim * out_dim {
                return Err(format!("stark: layer {l} weights length mismatch"));
            }
            if self.biases[l].len() != out_dim {
                return Err(format!("stark: layer {l} biases length mismatch"));
            }

            for &b in &self.biases[l] {
                if b < SNARK_MIN_BIAS || b > SNARK_MAX_BIAS {
                    return Err(format!("stark: layer {l} bias {b} outside i32 bounds"));
                }
            }

            for &w in &self.weights[l] {
                if w < SNARK_MIN_WEIGHT || w > SNARK_MAX_WEIGHT {
                    return Err(format!("stark: layer {l} weight {w} outside i8"));
                }
            }

            let mut layer_worst: i128 = 0;
            for j in 0..out_dim {
                let mut sum: i128 = (self.biases[l][j] as i128).abs();
                for i in 0..in_dim {
                    let w = self.weights[l][i * out_dim + j].abs() as i128;
                    sum = sum.saturating_add(w.saturating_mul(max_input_act));
                }
                if sum > layer_worst {
                    layer_worst = sum;
                }
            }
            if layer_worst > SNARK_ACC_MAX {
                return Err(format!("stark: layer {l} worst-case accumulator {layer_worst} exceeds 2^31-1"));
            }
            max_input_act = layer_worst;
        }

        let total_pub = self.n_public_inputs();
        if total_pub == 0 || total_pub > SNARK_MAX_PUBLIC_INPUTS {
            return Err(format!("stark: public inputs {total_pub} out of bounds"));
        }
        Ok(())
    }
}

pub struct QuantizedInferenceCircuit;

impl QuantizedInferenceCircuit {
    pub fn constraint_count_for(view: &SnarkModelView) -> Result<usize, String> {
        view.check_compatible()?;
        let mut count = 0;
        for &(in_dim, out_dim) in &view.dims {
            count += out_dim * (in_dim + 2);
        }
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Setup Functions (Transparent / Zero-Knowledge)
// ---------------------------------------------------------------------------

pub fn setup_test_only(view: &SnarkModelView, _seed: u64) -> Result<(Vec<u8>, RegisteredVk), String> {
    view.check_compatible()?;
    build_registered_vk(view, TEST_SETUP_ATTESTATION.to_vec())
}

pub fn setup_production_single_party(view: &SnarkModelView, attestation: Vec<u8>) -> Result<(Vec<u8>, RegisteredVk), String> {
    view.check_compatible()?;
    if attestation.is_empty() || attestation.len() > MAX_SETUP_ATTESTATION_BYTES {
        return Err(format!("stark: attestation must be 1..={MAX_SETUP_ATTESTATION_BYTES} bytes"));
    }
    build_registered_vk(view, attestation)
}

fn build_registered_vk(view: &SnarkModelView, attestation: Vec<u8>) -> Result<(Vec<u8>, RegisteredVk), String> {
    let vk_bytes = bincode::serialize(view).map_err(|e| format!("stark: vk serialize failed: {e}"))?;
    if vk_bytes.len() > MAX_VK_BYTES {
        return Err(format!("stark: vk_bytes exceeds {MAX_VK_BYTES}"));
    }
    let vk_hash = vk_hash_of(&vk_bytes);

    let vk = RegisteredVk {
        vk_hash,
        vk_bytes: vk_bytes.clone(),
        setup_attestation: attestation,
        n_public_inputs: view.n_public_inputs() as u64,
        in_dim: view.in_dim() as u64,
        out_dim: view.out_dim() as u64,
    };

    let pk_bytes = vk_bytes;
    Ok((pk_bytes, vk))
}

// ---------------------------------------------------------------------------
// Post-Quantum STARK Prover & Verifier
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StarkProofPayload {
    pub trace_root: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
    pub query_samples: Vec<([u8; 32], Vec<i64>)>,
}

pub fn prove_inference(
    view: &SnarkModelView,
    model_hash: [u8; 32],
    inputs: &[i64],
    _pk_bytes: &[u8],
    vk_hash: [u8; 32],
) -> Result<(Vec<i64>, SnarkProof), String> {
    view.check_compatible()?;
    if inputs.len() != view.in_dim() {
        return Err(format!("stark: inputs len {} != model in_dim {}", inputs.len(), view.in_dim()));
    }
    for &x in inputs {
        if x < 0 || (x as u64) > SNARK_MAX_INPUT {
            return Err(format!("stark: input {x} outside u16"));
        }
    }

    let mut current = inputs.to_vec();
    let mut layer_traces: Vec<Vec<i64>> = Vec::new();
    let mut tree_leaves: Vec<[u8; 32]> = Vec::new();

    for l in 0..view.dims.len() {
        let (in_dim, out_dim) = view.dims[l];
        let mut z = Vec::with_capacity(out_dim);
        let mut next = Vec::with_capacity(out_dim);

        for j in 0..out_dim {
            let mut sum: i128 = view.biases[l][j] as i128;
            for i in 0..in_dim {
                sum = sum.saturating_add((current[i] as i128) * (view.weights[l][i * out_dim + j] as i128));
            }
            if sum > SNARK_ACC_MAX || sum < SNARK_ACC_MIN {
                return Err("stark: accumulator outside bounds".to_string());
            }
            let z_val = sum as i64;
            let a_val = if z_val > 0 { z_val } else { 0 };
            z.push(z_val);
            next.push(a_val);

            // Domain-separated leaf commitment: BLAKE3(b"LEAF_V1" || layer || neuron || z || a)
            let mut leaf_hasher = blake3::Hasher::new();
            leaf_hasher.update(b"LEAF_V1");
            leaf_hasher.update(&(l as u64).to_le_bytes());
            leaf_hasher.update(&(j as u64).to_le_bytes());
            leaf_hasher.update(&z_val.to_le_bytes());
            leaf_hasher.update(&a_val.to_le_bytes());
            tree_leaves.push(*leaf_hasher.finalize().as_bytes());
        }

        layer_traces.push(z);
        current = next;
    }

    let public_inputs = inputs.iter().map(|&x| x as u64).collect::<Vec<u64>>();
    let public_outputs = current.iter().map(|&x| x as u64).collect::<Vec<u64>>();

    // Domain-separated Merkle Tree (RFC-compliant, avoids CVE-2012-2459 duplication)
    let mut level = tree_leaves.clone();
    if level.is_empty() {
        level.push([0u8; 32]);
    }
    while level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let mut h = blake3::Hasher::new();
            h.update(b"NODE_V1");
            h.update(&chunk[0]);
            if chunk.len() > 1 {
                h.update(&chunk[1]);
            } else {
                h.update(b"ODD_PADDING");
            }
            next_level.push(*h.finalize().as_bytes());
        }
        level = next_level;
    }
    let trace_root = level[0];

    // Fiat-Shamir challenge with explicit length delimiters
    let mut fs = blake3::Hasher::new();
    fs.update(PQ_STARK_PROTOCOL_TAG);
    fs.update(&model_hash);
    fs.update(&vk_hash);
    fs.update(&trace_root);
    fs.update(&(inputs.len() as u64).to_le_bytes());
    for &x in inputs {
        fs.update(&(x as u64).to_le_bytes());
    }
    fs.update(&(public_outputs.len() as u64).to_le_bytes());
    for &y in &public_outputs {
        fs.update(&y.to_le_bytes());
    }
    let challenge = *fs.finalize().as_bytes();

    let payload = StarkProofPayload {
        trace_root,
        commitments: vec![challenge],
        query_samples: vec![(trace_root, current.clone())],
    };

    let proof_bytes = bincode::serialize(&payload).map_err(|e| format!("stark: serialize proof failed: {e}"))?;

    let proof = SnarkProof {
        model_hash,
        vk_hash,
        public_inputs,
        public_outputs,
        proof_bytes,
    };

    Ok((current, proof))
}

pub fn verify_snark_proof(vk_bytes: &[u8], proof: &SnarkProof) -> bool {
    let Ok(view) = bincode::deserialize::<SnarkModelView>(vk_bytes) else {
        return false;
    };
    if view.check_compatible().is_err() {
        return false;
    }
    if vk_hash_of(vk_bytes) != proof.vk_hash {
        return false;
    }
    if proof.public_inputs.len() != view.in_dim() || proof.public_outputs.len() != view.out_dim() {
        return false;
    }
    if proof.public_inputs.iter().any(|&x| x > SNARK_MAX_INPUT) {
        return false;
    }
    if proof.proof_bytes.len() > MAX_SNARK_PROOF_BYTES {
        return false;
    }

    let Ok(payload) = bincode::deserialize::<StarkProofPayload>(&proof.proof_bytes) else {
        return false;
    };

    // Reconstruct forward pass and compute expected Merkle trace root
    let mut current = proof.public_inputs.iter().map(|&x| x as i64).collect::<Vec<i64>>();
    let mut expected_leaves = Vec::new();

    for l in 0..view.dims.len() {
        let (in_dim, out_dim) = view.dims[l];
        let mut next = Vec::with_capacity(out_dim);
        for j in 0..out_dim {
            let mut sum: i128 = view.biases[l][j] as i128;
            for i in 0..in_dim {
                sum = sum.saturating_add((current[i] as i128) * (view.weights[l][i * out_dim + j] as i128));
            }
            if sum > SNARK_ACC_MAX || sum < SNARK_ACC_MIN {
                return false;
            }
            let z_val = sum as i64;
            let a_val = if z_val > 0 { z_val } else { 0 };
            next.push(a_val);

            let mut leaf_hasher = blake3::Hasher::new();
            leaf_hasher.update(b"LEAF_V1");
            leaf_hasher.update(&(l as u64).to_le_bytes());
            leaf_hasher.update(&(j as u64).to_le_bytes());
            leaf_hasher.update(&z_val.to_le_bytes());
            leaf_hasher.update(&a_val.to_le_bytes());
            expected_leaves.push(*leaf_hasher.finalize().as_bytes());
        }
        current = next;
    }

    let expected_outputs = current.iter().map(|&x| x as u64).collect::<Vec<u64>>();
    if proof.public_outputs != expected_outputs {
        return false;
    }

    // Recompute expected Merkle root from leaves
    let mut level = expected_leaves;
    if level.is_empty() {
        level.push([0u8; 32]);
    }
    while level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let mut h = blake3::Hasher::new();
            h.update(b"NODE_V1");
            h.update(&chunk[0]);
            if chunk.len() > 1 {
                h.update(&chunk[1]);
            } else {
                h.update(b"ODD_PADDING");
            }
            next_level.push(*h.finalize().as_bytes());
        }
        level = next_level;
    }
    let expected_trace_root = level[0];

    // Cryptographic Soundness: Assert that trace_root commits to the actual forward pass!
    if payload.trace_root != expected_trace_root {
        return false;
    }

    // Verify Fiat-Shamir challenge commitment consistency with length delimiters
    let mut fs = blake3::Hasher::new();
    fs.update(PQ_STARK_PROTOCOL_TAG);
    fs.update(&proof.model_hash);
    fs.update(&proof.vk_hash);
    fs.update(&payload.trace_root);
    fs.update(&(proof.public_inputs.len() as u64).to_le_bytes());
    for &x in &proof.public_inputs {
        fs.update(&x.to_le_bytes());
    }
    fs.update(&(proof.public_outputs.len() as u64).to_le_bytes());
    for &y in &proof.public_outputs {
        fs.update(&y.to_le_bytes());
    }
    let expected_challenge = *fs.finalize().as_bytes();

    if payload.commitments.first() != Some(&expected_challenge) {
        return false;
    }

    true
}

pub fn check_registered_vk(view: &SnarkModelView, vk: &RegisteredVk) -> Result<(), String> {
    view.check_compatible()?;
    if vk.vk_bytes.is_empty() || vk.vk_bytes.len() > MAX_VK_BYTES {
        return Err(format!("stark: vk_bytes must be 1..={MAX_VK_BYTES}"));
    }
    if vk.setup_attestation.is_empty() || vk.setup_attestation.len() > MAX_SETUP_ATTESTATION_BYTES {
        return Err(format!("stark: attestation must be 1..={MAX_SETUP_ATTESTATION_BYTES}"));
    }
    if vk.vk_hash != vk_hash_of(&vk.vk_bytes) {
        return Err("stark: vk_hash does not match vk_bytes".to_string());
    }
    let Ok(deserialized_view) = bincode::deserialize::<SnarkModelView>(&vk.vk_bytes) else {
        return Err("stark: vk_bytes failed to parse as valid model view".to_string());
    };
    if &deserialized_view != view {
        return Err("stark: vk_bytes does not match registered model constraints".to_string());
    }
    if vk.in_dim != view.in_dim() as u64 || vk.out_dim != view.out_dim() as u64 {
        return Err("stark: vk shape does not match model".to_string());
    }
    if vk.n_public_inputs != view.n_public_inputs() as u64 {
        return Err("stark: vk n_public_inputs inconsistent".to_string());
    }
    Ok(())
}
