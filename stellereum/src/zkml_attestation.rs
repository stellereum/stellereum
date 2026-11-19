//! Post-quantum **attestation** engine for quantized inference.
//!
//! # ⚠️ THIS IS NOT A ZERO-KNOWLEDGE PROOF SYSTEM
//!
//! **Read this before calling anything here a "SNARK", a "STARK" or "zk".**
//! The audit that flagged this module (production blocker A5) was right about
//! the code and the old name was wrong:
//!
//! * **It is NOT a SNARK.** There is no R1CS, no AIR, no polynomial
//!   commitment, no polynomial IOP, no Fiat–Shamir transcript over a
//!   constraint system, and **no pairings**. Nothing is proved; nothing is
//!   checked with an elliptic curve.
//! * **It is NOT a STARK.** There is no trace-length/polynomial-degree
//!   argument, no FRI, no DEEP-FRI, no grinding. The "Merkle trace root" is a
//!   BLAKE3 Merkle tree over the layer activations, and the verifier
//!   **recomputes every leaf of it from scratch**.
//! * **It is NOT zero-knowledge.** The public inputs and the public outputs
//!   are IN THE CLEAR in the proof, and the verifier holds the whole model,
//!   so it learns the entire computation. There is no hiding.
//! * **It is NOT succinct.** Verification re-runs the whole quantized forward
//!   pass, so the verifier's cost is linear in the model's parameter count —
//!   exactly what a ZK proof is supposed to avoid.
//!
//! # What it actually is
//!
//! A **sound re-execution attestation** with a hash binding:
//!
//! 1. The verifier holds the model (the registered [`ModelSpec`], whose bytes
//!    are the model's constrained weights/biases/shape).
//! 2. The verifier **re-executes** the model on the proof's public inputs.
//! 3. The verifier recomputes the BLAKE3 Merkle trace root over the layer
//!    activations and compares it with the root the proof carries.
//! 4. The verifier recomputes the Fiat–Shamir challenge over
//!    `(model_hash, spec_hash, trace_root, inputs, outputs)` and compares it
//!    with the commitment the proof carries.
//! 5. The verifier checks that the claimed outputs are exactly the ones the
//!    re-execution produced.
//!
//! The claim this supports is precisely: **"these outputs are what THIS model
//! produces on THESE inputs."** That is a real and useful statement, and it is
//! what `OpCode::SysCallVerifyZkMlReexec` and
//! `OpCode::SysCallVerifyZkMlAttestation` both check — but the chain CANNOT
//! act on the verdict: there is no branch, no event, and `apply.rs` drops the
//! execution result's `return_value`. A verify is an EVENT, not a branch
//! condition; a value-bearing decision has to be made off chain from the
//! (public) payload.
//!
//! # What is TRUSTED
//!
//! * **The model.** The verifier must hold the exact model the proof claims
//!   to be about. On chain that is the committed model registry (append-only,
//!   first writer wins) plus the model hash. Off chain it is the registered
//!   spec the verifier was given.
//! * **The registry's append-only discipline.** A model id cannot be
//!   re-pointed to different weights: re-registering the SAME id with
//!   byte-identical bytes is idempotent (`Ok`, same hash) and is not a
//!   replacement, while a different weight set under a taken id is refused.
//!   So the weights a proof is checked against cannot be swapped after the
//!   fact.
//! * **The constrained format.** i8 weights, u16 inputs, a bounded
//!   accumulator, capped dimensions — so the re-execution cannot overflow or
//!   become unbounded work.
//! * **The `setup_attestation` label is NOT trusted and NOT a setup.** It is a
//!   free-form operator string. The chain refuses the documented test-only
//!   prefix (`TEST-ONLY-DETERMINISTIC-SETUP`) because a deterministic,
//!   waste-derivable setup must never anchor a chain — but there is **no
//!   ceremony, no toxic waste and no Powers-of-Tau** behind it, because there
//!   is nothing to set up. It is a LABEL, and it is not part of any
//!   cryptographic argument.
//!
//! # The machine-readable statement
//!
//! [`crate::zkml::zkml_capabilities`] returns exactly the above as data, and
//! the RPC serves it as `stell_zkmlCapabilities`. A wallet, an indexer or an
//! integrator should read THAT, not the opcode names: the opcodes were
//! renamed in this wave precisely because their old names (`...VerifyZkMlIn`,
//! `...VerifyZkMlSnark`, `...RegisterZkMlVk`) promised zero-knowledge and
//! succinctness that the code never delivered.
//!
//! # What a real ZK proof would need
//!
//! A circuit (R1CS/AIR) over the quantized forward pass, a polynomial
//! commitment scheme with a soundness argument, a Fiat–Shamir transcript over
//! that commitment, and — for the succinctness that matters here — a way to
//! verify a large model without running it. Until that lands, the honest
//! description of this subsystem is **"verifiable inference by
//! re-execution"**, and that is what the code and the docs now say.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Bounds (The Constrained Format)
// ---------------------------------------------------------------------------

pub const ATTEST_MAX_INPUT: u64 = 65_535;
pub const ATTEST_INPUT_BITS: usize = 16;
pub const ATTEST_MIN_WEIGHT: i64 = -128;
pub const ATTEST_MAX_WEIGHT: i64 = 127;
pub const ATTEST_MIN_BIAS: i64 = -(1i64 << 31);
pub const ATTEST_MAX_BIAS: i64 = (1i64 << 31) - 1;
pub const ATTEST_ACC_BITS: usize = 31;
pub const ATTEST_ACC_RANGE_BITS: usize = 32;
pub const ATTEST_ACC_MAX: i128 = (1i128 << 31) - 1;
pub const ATTEST_ACC_MIN: i128 = -(1i128 << 31);
pub const ATTEST_ACT_MAX: i128 = (1i128 << 32) - 1;
pub const ATTEST_MAX_DIM: usize = 128;
pub const ATTEST_MAX_LAYERS: usize = 8;
pub const ATTEST_MAX_PUBLIC_INPUTS: usize = 1024;
pub const ATTEST_PROOF_BYTES: usize = 192;
pub const MAX_ATTESTATION_PROOF_BYTES: usize = 65_536;
pub const MAX_MODEL_SPEC_BYTES: usize = 65_536;
pub const MAX_SETUP_ATTESTATION_BYTES: usize = 1024;

pub const TEST_SETUP_ATTESTATION: &[u8] = b"TEST-ONLY-DETERMINISTIC-SETUP:v1:StdRng-seed-domain-ATTEST-TEST;WASTE-DERIVABLE-NOT-FOR-PRODUCTION";

/// Fiat–Shamir domain tag for the UNBOUND attestation transcript.
///
/// ⚠️ LEGACY NAME — the bytes are committed and must not change: this tag is
/// part of every existing `AttestationProof` preimage, so renaming it would
/// move the transcript (and therefore acceptance) for every proof ever made.
/// Despite `PQ_STARK_BLAKE3` in the name, the mechanism is **re-execution with
/// a BLAKE3 Merkle trace root and a Fiat–Shamir hash** — there is no STARK,
/// no FRI, no polynomial commitment and no post-quantum-specific step here
/// (the hash is BLAKE3, whose collision resistance is a separate assumption).
/// A correctly-named tag can only be introduced with a NEW FS domain behind a
/// gate; see [`ZKML_ATTESTATION_CONTEXT_TAG`].
pub const ZKML_ATTESTATION_PROTOCOL_TAG: &[u8] = b"STELLEREUM_PQ_STARK_BLAKE3_V1";

/// Fiat–Shamir domain tag for the OPT-IN, context-bound transcript.
///
/// This tag is used ONLY by [`prove_attestation_bound`] /
/// [`verify_attestation_bound`] / [`verify_attestation_at`] when
/// [`zkml_context_binding_active`] is true. It is a NEW domain, so a bound
/// proof and an unbound proof can never verify under each other's rules. The
/// legacy [`ZKML_ATTESTATION_PROTOCOL_TAG`] remains byte-identical for the
/// current consensus path.
pub const ZKML_ATTESTATION_CONTEXT_TAG: &[u8] = b"STELLEREUM_INFERENCE_CTX_V1";

/// Hard-fork height at which context-bound attestation transcripts become
/// mandatory. `u64::MAX` means **never**: today's unbound transcript is the
/// only one accepted, and every code path below is byte-identical to before.
///
/// Changing this value changes acceptance (old proofs stop verifying), so it
/// may only move with a spec update and a coordinated hard fork. The bound
/// API exists so the seam is testable now without touching consensus.
pub const ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// What a context-bound proof is bound TO. Committing these into the FS
/// transcript turns a proof from a permanent bearer token into one that is
/// only valid for (chain, model id, height, sender).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkmlContextBinding {
    pub chain_id: u64,
    pub model_id: [u8; 32],
    pub height: u64,
    pub sender: [u8; 32],
}

#[cfg(test)]
thread_local! {
    /// Test-only override of [`ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT`].
    /// Thread-local so parallel unit tests cannot perturb each other; absent
    /// outside `cfg(test)` so a release node has no local gate knob at all
    /// (a node-local gate that changes acceptance would be a chain split).
    static CONTEXT_BINDING_HEIGHT_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// The activation height in force for this build/thread.
///
/// In production this is always [`ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT`]
/// (`u64::MAX`); only unit tests can lower it.
pub fn zkml_context_binding_activation_height() -> u64 {
    #[cfg(test)]
    {
        if let Some(h) = CONTEXT_BINDING_HEIGHT_OVERRIDE.with(std::cell::Cell::get) {
            return h;
        }
    }
    ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT
}

/// TEST-ONLY: override (or clear, with `None`) the gate height for the
/// CURRENT thread. Not compiled into a release lib, so it cannot be used to
/// fork a live chain.
#[cfg(test)]
pub fn set_zkml_context_binding_activation_height_for_tests(height: Option<u64>) {
    CONTEXT_BINDING_HEIGHT_OVERRIDE.with(|c| c.set(height));
}

/// Is the context-bound transcript mandatory at `height`?
///
/// False by default in every build (`u64::MAX`), which is what keeps today's
/// wire format, verdicts and state root byte-identical.
pub fn zkml_context_binding_active(height: u64) -> bool {
    height >= zkml_context_binding_activation_height()
}

// ---------------------------------------------------------------------------
// Wire Types
// ---------------------------------------------------------------------------

/// A verifying key committed on chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSpec {
    /// SHA256(spec_bytes), matching key for verify.
    pub spec_hash: [u8; 32],
    /// Serialized model constraints and shape.
    pub spec_bytes: Vec<u8>,
    /// Setup attestation tag.
    pub setup_attestation: Vec<u8>,
    pub n_public_inputs: u64,
    pub in_dim: u64,
    pub out_dim: u64,
}

/// An inference attestation: a re-executed forward pass plus its BLAKE3 trace
/// root. NOT a "Post-Quantum STARK" proof (the historic doc line said so; it
/// was wrong). There is no STARK, no circuit and no zero-knowledge here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProof {
    pub model_hash: [u8; 32],
    pub spec_hash: [u8; 32],
    pub public_inputs: Vec<u64>,
    pub public_outputs: Vec<u64>,
    pub proof_bytes: Vec<u8>,
}

impl AttestationProof {
    pub fn wire_len(&self) -> usize {
        self.proof_bytes
            .len()
            .saturating_add(self.public_inputs.len().saturating_mul(8))
            .saturating_add(self.public_outputs.len().saturating_mul(8))
            .saturating_add(64)
    }
}

pub fn spec_hash_of(spec_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(spec_bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Model View & Constraints
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelView {
    pub weights: Vec<Vec<i64>>,
    pub biases: Vec<Vec<i64>>,
    pub dims: Vec<(usize, usize)>,
}

impl ModelView {
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
        if n_layers == 0 || n_layers > ATTEST_MAX_LAYERS {
            return Err(format!(
                "attestation: need 1..={ATTEST_MAX_LAYERS} layers, got {n_layers}"
            ));
        }
        if self.weights.len() != n_layers || self.biases.len() != n_layers {
            return Err("attestation: weights/biases/dims length mismatch".to_string());
        }

        let mut expect_in: Option<usize> = None;
        let mut max_input_act: i128 = ATTEST_MAX_INPUT as i128;
        for l in 0..n_layers {
            let (in_dim, out_dim) = self.dims[l];
            if in_dim == 0 || in_dim > ATTEST_MAX_DIM || out_dim == 0 || out_dim > ATTEST_MAX_DIM {
                return Err(format!("attestation: layer {l} dims out of bounds"));
            }
            if let Some(want) = expect_in {
                if in_dim != want {
                    return Err(format!(
                        "attestation: layer {l} not chained (in={in_dim}, want={want})"
                    ));
                }
            }
            expect_in = Some(out_dim);

            if self.weights[l].len() != in_dim * out_dim {
                return Err(format!("attestation: layer {l} weights length mismatch"));
            }
            if self.biases[l].len() != out_dim {
                return Err(format!("attestation: layer {l} biases length mismatch"));
            }

            for &b in &self.biases[l] {
                if !(ATTEST_MIN_BIAS..=ATTEST_MAX_BIAS).contains(&b) {
                    return Err(format!(
                        "attestation: layer {l} bias {b} outside i32 bounds"
                    ));
                }
            }

            for &w in &self.weights[l] {
                if !(ATTEST_MIN_WEIGHT..=ATTEST_MAX_WEIGHT).contains(&w) {
                    return Err(format!("attestation: layer {l} weight {w} outside i8"));
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
            if layer_worst > ATTEST_ACC_MAX {
                return Err(format!(
                    "attestation: layer {l} worst-case accumulator {layer_worst} exceeds 2^31-1"
                ));
            }
            max_input_act = layer_worst;
        }

        let total_pub = self.n_public_inputs();
        if total_pub == 0 || total_pub > ATTEST_MAX_PUBLIC_INPUTS {
            return Err(format!(
                "attestation: public inputs {total_pub} out of bounds"
            ));
        }
        Ok(())
    }
}

pub struct InferenceCostModel;

impl InferenceCostModel {
    pub fn constraint_count_for(view: &ModelView) -> Result<usize, String> {
        view.check_compatible()?;
        let mut count = 0;
        for &(in_dim, out_dim) in &view.dims {
            count += out_dim * (in_dim + 2);
        }
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Model-spec construction (there is NO setup: these are format commitments)
// ---------------------------------------------------------------------------

/// Test-only deterministic setup (fixed attestation): integration tests use
/// this for off-chain setup -> on-chain VK pinning. Absent from production
/// builds (`any(test, debug_assertions)` only).
#[cfg(any(test, debug_assertions))]
pub fn model_spec_test_only(view: &ModelView, _seed: u64) -> Result<(Vec<u8>, ModelSpec), String> {
    view.check_compatible()?;
    build_model_spec(view, TEST_SETUP_ATTESTATION.to_vec())
}

pub fn model_spec_with_attestation(
    view: &ModelView,
    attestation: Vec<u8>,
) -> Result<(Vec<u8>, ModelSpec), String> {
    view.check_compatible()?;
    if attestation.is_empty() || attestation.len() > MAX_SETUP_ATTESTATION_BYTES {
        return Err(format!(
            "attestation: attestation must be 1..={MAX_SETUP_ATTESTATION_BYTES} bytes"
        ));
    }
    build_model_spec(view, attestation)
}

fn build_model_spec(
    view: &ModelView,
    attestation: Vec<u8>,
) -> Result<(Vec<u8>, ModelSpec), String> {
    let spec_bytes =
        bincode::serialize(view).map_err(|e| format!("attestation: vk serialize failed: {e}"))?;
    if spec_bytes.len() > MAX_MODEL_SPEC_BYTES {
        return Err(format!(
            "attestation: spec_bytes exceeds {MAX_MODEL_SPEC_BYTES}"
        ));
    }
    let spec_hash = spec_hash_of(&spec_bytes);

    let vk = ModelSpec {
        spec_hash,
        spec_bytes: spec_bytes.clone(),
        setup_attestation: attestation,
        n_public_inputs: view.n_public_inputs() as u64,
        in_dim: view.in_dim() as u64,
        out_dim: view.out_dim() as u64,
    };

    let pk_bytes = spec_bytes;
    Ok((pk_bytes, vk))
}

// ---------------------------------------------------------------------------
// Attestation Prover & Verifier (re-execution, no STARK)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AttestationPayload {
    pub trace_root: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
    pub query_samples: Vec<([u8; 32], Vec<i64>)>,
}

/// The one Fiat–Shamir transcript used by BOTH sides.
///
/// `None` = the legacy unbound domain ([`ZKML_ATTESTATION_PROTOCOL_TAG`]),
/// byte-identical to every proof the chain has ever accepted. `Some` = the
/// opt-in context-bound domain ([`ZKML_ATTESTATION_CONTEXT_TAG`]) which
/// additionally commits `chain_id || model_id || height || sender`. Because
/// prove and verify call the SAME function, the two can never drift.
fn attestation_challenge(
    binding: Option<&ZkmlContextBinding>,
    model_hash: &[u8; 32],
    spec_hash: &[u8; 32],
    trace_root: &[u8; 32],
    inputs: &[u64],
    outputs: &[u64],
) -> [u8; 32] {
    let mut fs = blake3::Hasher::new();
    match binding {
        None => {
            fs.update(ZKML_ATTESTATION_PROTOCOL_TAG);
        }
        Some(b) => {
            fs.update(ZKML_ATTESTATION_CONTEXT_TAG);
            fs.update(&b.chain_id.to_le_bytes());
            fs.update(&b.model_id);
            fs.update(&b.height.to_le_bytes());
            fs.update(&b.sender);
        }
    }
    fs.update(model_hash);
    fs.update(spec_hash);
    fs.update(trace_root);
    fs.update(&(inputs.len() as u64).to_le_bytes());
    for &x in inputs {
        fs.update(&x.to_le_bytes());
    }
    fs.update(&(outputs.len() as u64).to_le_bytes());
    for &y in outputs {
        fs.update(&y.to_le_bytes());
    }
    *fs.finalize().as_bytes()
}

/// Produce a re-execution attestation for `inputs` under the UNBOUND transcript
/// (today's consensus format, byte-identical).
pub fn prove_attestation(
    view: &ModelView,
    model_hash: [u8; 32],
    inputs: &[i64],
    pk_bytes: &[u8],
    spec_hash: [u8; 32],
) -> Result<(Vec<i64>, AttestationProof), String> {
    prove_attestation_inner(view, model_hash, inputs, pk_bytes, spec_hash, None)
}

/// Produce a CONTEXT-BOUND attestation (opt-in, separate FS domain).
///
/// The proof will only verify through [`verify_attestation_bound`] (or
/// [`verify_attestation_at`] once the gate is open) with the SAME binding -
/// it is not a bearer token. It does NOT verify through the legacy
/// [`verify_attestation`], and a legacy proof does not verify here.
pub fn prove_attestation_bound(
    view: &ModelView,
    model_hash: [u8; 32],
    inputs: &[i64],
    pk_bytes: &[u8],
    spec_hash: [u8; 32],
    binding: &ZkmlContextBinding,
) -> Result<(Vec<i64>, AttestationProof), String> {
    prove_attestation_inner(view, model_hash, inputs, pk_bytes, spec_hash, Some(binding))
}

fn prove_attestation_inner(
    view: &ModelView,
    model_hash: [u8; 32],
    inputs: &[i64],
    _pk_bytes: &[u8],
    spec_hash: [u8; 32],
    binding: Option<&ZkmlContextBinding>,
) -> Result<(Vec<i64>, AttestationProof), String> {
    view.check_compatible()?;
    if inputs.len() != view.in_dim() {
        return Err(format!(
            "attestation: inputs len {} != model in_dim {}",
            inputs.len(),
            view.in_dim()
        ));
    }
    for &x in inputs {
        if x < 0 || (x as u64) > ATTEST_MAX_INPUT {
            return Err(format!("attestation: input {x} outside u16"));
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
            for (i, &c) in current.iter().enumerate().take(in_dim) {
                sum = sum.saturating_add((c as i128) * (view.weights[l][i * out_dim + j] as i128));
            }
            if !(ATTEST_ACC_MIN..=ATTEST_ACC_MAX).contains(&sum) {
                return Err("attestation: accumulator outside bounds".to_string());
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

    // Fiat-Shamir challenge with explicit length delimiters. `binding == None`
    // is the legacy transcript, byte-for-byte what it always was.
    let challenge = attestation_challenge(
        binding,
        &model_hash,
        &spec_hash,
        &trace_root,
        &public_inputs,
        &public_outputs,
    );

    let payload = AttestationPayload {
        trace_root,
        commitments: vec![challenge],
        query_samples: vec![(trace_root, current.clone())],
    };

    let proof_bytes = bincode::serialize(&payload)
        .map_err(|e| format!("attestation: serialize proof failed: {e}"))?;

    let proof = AttestationProof {
        model_hash,
        spec_hash,
        public_inputs,
        public_outputs,
        proof_bytes,
    };

    Ok((current, proof))
}

/// Verify a re-execution attestation under the UNBOUND transcript (today's
/// consensus format).
pub fn verify_attestation(spec_bytes: &[u8], proof: &AttestationProof) -> bool {
    verify_attestation_inner(spec_bytes, proof, None)
}

/// Verify a CONTEXT-BOUND attestation (opt-in, separate FS domain).
///
/// A legacy proof fails here and a bound proof fails
/// [`verify_attestation`]: the two transcripts are distinct domains.
pub fn verify_attestation_bound(
    spec_bytes: &[u8],
    proof: &AttestationProof,
    binding: &ZkmlContextBinding,
) -> bool {
    verify_attestation_inner(spec_bytes, proof, Some(binding))
}

/// Gate-aware entry point: today it is a literal call to
/// [`verify_attestation`] (the binding argument is IGNORED while the gate is
/// closed, so a caller cannot opt into a fork by accident). At or after
/// [`ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT`] a binding is REQUIRED and only
/// the bound transcript verifies.
pub fn verify_attestation_at(
    spec_bytes: &[u8],
    proof: &AttestationProof,
    height: u64,
    binding: Option<&ZkmlContextBinding>,
) -> bool {
    if !zkml_context_binding_active(height) {
        return verify_attestation(spec_bytes, proof);
    }
    match binding {
        Some(b) => verify_attestation_bound(spec_bytes, proof, b),
        None => false,
    }
}

fn verify_attestation_inner(
    spec_bytes: &[u8],
    proof: &AttestationProof,
    binding: Option<&ZkmlContextBinding>,
) -> bool {
    let Ok(view) = bincode::deserialize::<ModelView>(spec_bytes) else {
        return false;
    };
    if view.check_compatible().is_err() {
        return false;
    }
    if spec_hash_of(spec_bytes) != proof.spec_hash {
        return false;
    }
    if proof.public_inputs.len() != view.in_dim() || proof.public_outputs.len() != view.out_dim() {
        return false;
    }
    if proof.public_inputs.iter().any(|&x| x > ATTEST_MAX_INPUT) {
        return false;
    }
    if proof.proof_bytes.len() > MAX_ATTESTATION_PROOF_BYTES {
        return false;
    }

    let Ok(payload) = bincode::deserialize::<AttestationPayload>(&proof.proof_bytes) else {
        return false;
    };

    // Reconstruct forward pass and compute expected Merkle trace root
    let mut current = proof
        .public_inputs
        .iter()
        .map(|&x| x as i64)
        .collect::<Vec<i64>>();
    let mut expected_leaves = Vec::new();

    for l in 0..view.dims.len() {
        let (in_dim, out_dim) = view.dims[l];
        let mut next = Vec::with_capacity(out_dim);
        for j in 0..out_dim {
            let mut sum: i128 = view.biases[l][j] as i128;
            for (i, &c) in current.iter().enumerate().take(in_dim) {
                sum = sum.saturating_add((c as i128) * (view.weights[l][i * out_dim + j] as i128));
            }
            if !(ATTEST_ACC_MIN..=ATTEST_ACC_MAX).contains(&sum) {
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

    // The trace root must equal the one recomputed from the forward pass.
    // There is NO "cryptographic soundness" from the commitment alone: the
    // root commits to the PROVER's claimed activations too, so soundness here
    // comes from the fact that the verifier recomputed every leaf AND checked
    // `public_outputs` against the same forward pass above.
    if payload.trace_root != expected_trace_root {
        return false;
    }

    // Fiat-Shamir challenge commitment consistency with length delimiters.
    let expected_challenge = attestation_challenge(
        binding,
        &proof.model_hash,
        &proof.spec_hash,
        &payload.trace_root,
        &proof.public_inputs,
        &proof.public_outputs,
    );

    if payload.commitments.first() != Some(&expected_challenge) {
        return false;
    }

    true
}

pub fn check_model_spec(view: &ModelView, vk: &ModelSpec) -> Result<(), String> {
    view.check_compatible()?;
    if vk.spec_bytes.is_empty() || vk.spec_bytes.len() > MAX_MODEL_SPEC_BYTES {
        return Err(format!(
            "attestation: spec_bytes must be 1..={MAX_MODEL_SPEC_BYTES}"
        ));
    }
    if vk.setup_attestation.is_empty() || vk.setup_attestation.len() > MAX_SETUP_ATTESTATION_BYTES {
        return Err(format!(
            "attestation: attestation must be 1..={MAX_SETUP_ATTESTATION_BYTES}"
        ));
    }
    if vk.spec_hash != spec_hash_of(&vk.spec_bytes) {
        return Err("attestation: spec_hash does not match spec_bytes".to_string());
    }
    let Ok(deserialized_view) = bincode::deserialize::<ModelView>(&vk.spec_bytes) else {
        return Err("attestation: spec_bytes failed to parse as valid model view".to_string());
    };
    if &deserialized_view != view {
        return Err(
            "attestation: spec_bytes does not match registered model constraints".to_string(),
        );
    }
    if vk.in_dim != view.in_dim() as u64 || vk.out_dim != view.out_dim() as u64 {
        return Err("attestation: vk shape does not match model".to_string());
    }
    if vk.n_public_inputs != view.n_public_inputs() as u64 {
        return Err("attestation: vk n_public_inputs inconsistent".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod context_binding_tests {
    use super::*;
    use crate::zkml::{QuantizedLayer, QuantizedLinearModel};

    fn model() -> QuantizedLinearModel {
        // Same fixture as the zkml unit tests: [3, 4] -> [11, 7].
        QuantizedLinearModel::new(vec![QuantizedLayer::new(
            2,
            2,
            vec![2, -1, 1, 3],
            vec![1, -2],
        )])
    }

    fn setup() -> (QuantizedLinearModel, ModelSpec, Vec<u8>) {
        let m = model();
        let (pk, spec) = model_spec_with_attestation(&m.attestation_view(), b"label".to_vec())
            .expect("compatible model must produce a spec");
        (m, spec, pk)
    }

    fn binding(model_id: [u8; 32]) -> ZkmlContextBinding {
        ZkmlContextBinding {
            chain_id: 5_757,
            model_id,
            height: 42,
            sender: [0x77; 32],
        }
    }

    /// Regression for the honesty rule: a user-visible refusal from this
    /// subsystem must never describe itself as a STARK/ZK proof. The error
    /// prefix used to be `stark:` — the mechanism never had a STARK.
    #[test]
    fn user_visible_errors_never_claim_stark_or_zero_knowledge() {
        let m = model();
        let view = m.attestation_view();
        let bad = ModelSpec {
            spec_hash: [0u8; 32],
            spec_bytes: Vec::new(),
            setup_attestation: b"label".to_vec(),
            n_public_inputs: 2,
            in_dim: 2,
            out_dim: 2,
        };
        let err = check_model_spec(&view, &bad).expect_err("empty spec_bytes must be refused");
        let lower = err.to_lowercase();
        assert!(
            !lower.contains("stark") && !lower.contains("zero-knowledge") && !lower.contains("zk"),
            "refusal must not claim a STARK/ZK proof: {err}"
        );
        assert!(
            err.starts_with("attestation:"),
            "refusal must name the real mechanism: {err}"
        );
    }

    #[test]
    fn gate_is_closed_by_default() {
        assert_eq!(ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT, u64::MAX);
        assert!(!zkml_context_binding_active(0));
        assert!(!zkml_context_binding_active(u64::MAX - 1));
    }

    #[test]
    fn bound_and_legacy_transcripts_do_not_cross_verify() {
        let (m, spec, pk) = setup();
        let ctx = binding([0x51; 32]);
        let (_, bound) = prove_attestation_bound(
            &m.attestation_view(),
            m.compute_model_hash(),
            &[3, 4],
            &pk,
            spec.spec_hash,
            &ctx,
        )
        .expect("bound prove must succeed");
        let (_, legacy) = prove_attestation(
            &m.attestation_view(),
            m.compute_model_hash(),
            &[3, 4],
            &pk,
            spec.spec_hash,
        )
        .expect("legacy prove must succeed");

        // Legacy proof is still accepted by the legacy verifier (byte-identical
        // format) and the bound proof is NOT.
        assert!(verify_attestation(&spec.spec_bytes, &legacy));
        assert!(!verify_attestation(&spec.spec_bytes, &bound));
        // ... and the converse.
        assert!(verify_attestation_bound(&spec.spec_bytes, &bound, &ctx));
        assert!(!verify_attestation_bound(&spec.spec_bytes, &legacy, &ctx));
    }

    #[test]
    fn every_bound_field_is_part_of_the_statement() {
        let (m, spec, pk) = setup();
        let ctx = binding([0x51; 32]);
        let (_, bound) = prove_attestation_bound(
            &m.attestation_view(),
            m.compute_model_hash(),
            &[3, 4],
            &pk,
            spec.spec_hash,
            &ctx,
        )
        .expect("bound prove must succeed");

        let mut wrong = ctx;
        wrong.chain_id += 1;
        assert!(!verify_attestation_bound(&spec.spec_bytes, &bound, &wrong));
        let mut wrong = ctx;
        wrong.model_id[0] ^= 1;
        assert!(!verify_attestation_bound(&spec.spec_bytes, &bound, &wrong));
        let mut wrong = ctx;
        wrong.height += 1;
        assert!(!verify_attestation_bound(&spec.spec_bytes, &bound, &wrong));
        let mut wrong = ctx;
        wrong.sender[0] ^= 1;
        assert!(!verify_attestation_bound(&spec.spec_bytes, &bound, &wrong));
    }

    #[test]
    fn gate_is_inert_until_the_test_override_opens_it() {
        let (m, spec, pk) = setup();
        let ctx = binding([0x51; 32]);
        let (_, bound) = prove_attestation_bound(
            &m.attestation_view(),
            m.compute_model_hash(),
            &[3, 4],
            &pk,
            spec.spec_hash,
            &ctx,
        )
        .expect("bound prove must succeed");

        // Gate closed at every real height: the context argument is IGNORED
        // and only the legacy transcript is accepted.
        assert!(!verify_attestation_at(
            &spec.spec_bytes,
            &bound,
            0,
            Some(&ctx)
        ));
        set_zkml_context_binding_activation_height_for_tests(Some(0));
        // Open: the binding is required and must match exactly.
        assert!(verify_attestation_at(
            &spec.spec_bytes,
            &bound,
            0,
            Some(&ctx)
        ));
        let mut wrong = ctx;
        wrong.chain_id += 1;
        assert!(!verify_attestation_at(
            &spec.spec_bytes,
            &bound,
            0,
            Some(&wrong)
        ));
        assert!(!verify_attestation_at(&spec.spec_bytes, &bound, 0, None));
        set_zkml_context_binding_activation_height_for_tests(None);
        assert!(!zkml_context_binding_active(0));
    }
}
