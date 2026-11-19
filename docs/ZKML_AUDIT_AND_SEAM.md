# zkML — Capability Audit and the Proof-System Seam

Status: read-only audit of the 2026-11-18 tree. No source or test file was
modified; this document is the only artifact.

Line numbers are from the files as they exist **now**. Anything I could not
confirm from source is marked **UNVERIFIED**.

Scope read: `stellereum/src/zkml.rs`, `stellereum/src/zkml_attestation.rs`,
`stellereum/src/svm.rs` (the two verify opcodes and their gas arms),
`stellereum/src/state_engine/apply.rs` (registry snapshot/commit),
`stellereum/src/rpc/{reads,streams,tests}.rs`, `stellereum/src/mempool.rs`,
`stellereum/src/commitment.rs`, `stellereum/src/state_engine/{accounts,types}.rs`,
`stellereum/src/storage.rs`, `stellereum/src/runtime/mod.rs`,
`docs/specs/03_VM_AND_EXECUTION_PHASE2.md`.

---

## 0. One-paragraph verdict

Both zkML verify opcodes are **sound re-execution checks** and neither is a
proof system. They prove exactly one statement — *"these outputs are the
deterministic integer forward pass of the model registered under this
`model_id`, on these inputs"* (`zkml.rs:1414-1422`,
`zkml_attestation.rs:26-43`) — and they prove it by running the model on every
node (`svm.rs:2772`, `svm.rs:2924`). There is no circuit, no commitment
scheme, no setup, no succinctness and no hiding (`zkml.rs:105-109`).

The real gaps are not "is it a SNARK". They are: (a) nothing on chain can
**consume** the verdict, (b) the model is **caller-chosen and permissionless**,
(c) the inputs are **not bound to anything**, and (d) the opcode's gas price
under-prices the work by roughly an order of magnitude. All four are
re-execution-independent and would survive a real proof system unchanged.

---

## 1. Exact capability audit

### 1.1 `SysCallVerifyZkMlReexec` (discriminant 35, `svm.rs:706-709`)

Handler: `svm.rs:2734-2779`. Model registry is a VM parameter
(`svm.rs:1340`, `svm.rs:1350`), not a `VmContext` field; it is cloned in
per-payload at `apply.rs:595-607` and committed back only on a fully applied
transaction (`apply.rs:1144-1148`).

| Question | Answer | Evidence |
|---|---|---|
| What is proven | `public_outputs == forward(A, public_inputs)` for the exact weights stored under `model_id` | `zkml.rs:1435-1479`; handler `svm.rs:2772` |
| Public inputs | `model_id` (opcode field), `proof.model_hash`, `proof.public_inputs`, `proof.public_outputs`, `proof.proof_bytes` (full activation trace) | `svm.rs:706-709`, `zkml.rs:1252-1257` |
| What the verifier re-executes | The entire forward pass: every layer, every neuron, `i64` saturating MACs + ReLU | `zkml.rs:1443-1452` → `zkml.rs:1132-1147` |
| Extra work the verifier does | Re-derives `model_hash` (SHA-256 per layer), then calls `verify_inference` which re-hashes the FS transcript and re-checks every ReLU, then **deserialises `proof_bytes` twice** | `zkml.rs:1439`, `zkml.rs:1463`, `zkml.rs:1467`, `zkml.rs:1500` |
| Model hash bound? | Yes, twice: handler compares to `rec.model_hash` (`svm.rs:2751`), then `verify_inference_against` recomputes from weights (`zkml.rs:1439`) | |
| Spec bound? | No. This opcode never reads `rec.spec` (`svm.rs:2734-2779`) | |
| Inputs committed? | Only inside the proof's own FS hash (`zkml.rs:1510-1527`). Nothing external (no chain id, height, sender, request id) | |
| Effect on state | None. `state.stack.push(1)` only (`svm.rs:2778`); `VmExecutionResult::Success.return_value` is discarded with `..` at `apply.rs:783-787` and never persisted | |
| Failure mode | Whole transaction reverts (`svm.rs:2742-2776`) | |
| Cost per call | `5_000 + 2·wire_len` in `opcode_gas` + `param_count` in the handler | `svm.rs:221-224`, `svm.rs:386`, `svm.rs:2760-2765` |

### 1.2 `SysCallVerifyZkMlAttestation` (discriminant 38, `svm.rs:805-808`)

Handler: `svm.rs:2837-2931`. Requires a registered `ModelSpec`
(`svm.rs:2870-2876`), attached once by `ZkMlModelRegistry::register_spec`
(`zkml.rs:1704-1726`).

| Question | Answer | Evidence |
|---|---|---|
| What is proven | Same statement, **plus**: proof names both the registered model hash and the registered spec hash, and the I/O shape matches the spec | `svm.rs:2864-2890` |
| Public inputs | `model_id`, `proof.{model_hash, spec_hash, public_inputs, public_outputs, proof_bytes}` | `zkml_attestation.rs:131-138` |
| What the verifier re-executes | The whole forward pass **from `spec.spec_bytes`**, plus `check_compatible` (O(params) worst-case accumulator re-derivation) and a full BLAKE3 Merkle tree over every neuron leaf | `zkml_attestation.rs:445-501` |
| Model hash bound? | Yes to the record (`svm.rs:2864`). ⚠️ **Inside `verify_attestation` the model hash is never derived from anything** — it is only a value fed into the FS hash (`zkml_attestation.rs:537-539`). Soundness depends entirely on the handler's `svm.rs:2864` check. A caller of the public helper alone gets an unsound `true` | |
| Spec bound to model? | Yes, at registration: `check_model_spec` demands `bincode(spec_bytes) == rec.model.attestation_view()` and a matching `spec_hash` | `zkml.rs:1722-1723`, `zkml_attestation.rs:570-584` |
| Inputs committed? | u16 range-checked (`svm.rs:2894-2902`), otherwise unconstrained and not bound to any external request | |
| Effect on state | None. `state.stack.push(1)` only (`svm.rs:2931`) | |
| Cost per call | `30_000 + 200·(in+out) + 2·wire_len` + `param_count` | `svm.rs:275-279`, `svm.rs:2838-2844`, `svm.rs:2918-2923` |

### 1.3 What the two opcodes do **not** give you

1. **No on-chain consumer.** The `OpCode` enum has no jump/branch/conditional
   call (`svm.rs:465-1100`; the only control-flow-ish ops are `Halt`, `Push`,
   `Pop`, arithmetic). The verdict is one stack value that no later opcode
   reads, the return value is dropped (`apply.rs:783-787`), no event is
   emitted, no state is written. **A zkML verify cannot gate a transfer,
   mint, or contract call.** Any "value-bearing decision" has to be made
   off-chain by re-reading the block payload — which contains the proof and is
   public anyway.
   *This directly softens the language at `zkml.rs:1421-1422` and
   `zkml_attestation.rs:40-41` ("what makes a value-bearing decision sound").*

2. **Model identity is chosen by the prover.** `register` is permissionless and
   `model_id` is caller-chosen (`zkml.rs:1633-1647`, `zkml.rs:1648-1679`).
   Nothing binds `model_id` to a governance namespace or an allowlist; the
   residual is acknowledged as deferred at `zkml.rs:1644-1647`. So "a zkML
   verify applied" means only "some model, registered by someone, produced
   these outputs". A consumer must independently pin the exact `model_id` it
   trusts; the chain does not.

3. **Inputs are prover-chosen and context-free.** The FS transcript covers
   `(protocol_tag, model_hash, spec_hash, trace_root, inputs, outputs)`
   (`zkml_attestation.rs:409-423`) and `(model_hash, inputs, outputs, traces)`
   for re-expercution (`zkml.rs:1378-1393`). It contains **no chain id, no
   `model_id`, no height, no sender, no request id**. A valid
   `AttestationProof` is a bearer token, replayable into any transaction, on
   any chain, forever. Today that is harmless because verification has no
   state effect; it is a hard blocker for any future "verify once, act later"
   design.

4. **The two opcodes accept different input domains.** Reexecution casts
   `u64 -> i64` with no range check (`zkml.rs:1443`) and never enforces the
   documented u16 range; attestation does (`svm.rs:2894-2902`,
   `zkml_attestation.rs:458`). A proof accepted by one can be rejected by the
   other; there is no cross-opcode equivalence to rely on.

5. **`layer_hash` in the reexecution trace is never compared to the model.**
   `verify_inference_against` compares only pre/post activations
   (`zkml.rs:1473-1477`); `verify_inference` merely folds `layer_hash` into the
   hash the prover itself computes (`zkml.rs:1518-1527`). This is not a
   soundness hole (the activations are compared), but it means the "Fiat–Shamir
   challenge" is a **hash of prover-chosen data**, not a proof. A forged,
   ReLU-consistent, self-hashed trace passes `verify_inference`
   (`zkml.rs:1822-1868`; the forging helper ships in release builds as
   `#[doc(hidden)] pub`, `zkml.rs:1314-1315`).

6. **Dead proof surface.** `AttestationPayload.query_samples` and every
   `commitments` entry after the first are ignored by the verifier
   (`zkml_attestation.rs:551`). Up to ~64 KiB of proof bytes are carried and
   never checked (`zkml_attestation.rs:461`, cap `MAX_ATTESTATION_PROOF_BYTES`).

7. **The `setup_attestation` label is unauthenticated.** `register_spec` is
   permissionless and first-writer-wins (`zkml.rs:1709-1715`), so anyone can
   attach a ceremonial-looking label to someone else's model. The only
   constraint is the `TEST-ONLY-DETERMINISTIC-SETUP` prefix refusal
   (`svm.rs:2813-2819`). Not a soundness hole — but it is exactly the field a
   reader would mistake for a setup commitment, and it is *not* covered by
   `spec_hash` (`zkml_attestation.rs:150-154` hashes `spec_bytes` only).

### 1.4 Real gaps, ranked

| # | Gap | Severity | Evidence |
|---|---|---|---|
| G1 | Verdict is unobservable on chain (no branch, no event, no stored return value) | **High** — the opcode cannot gate value | `svm.rs:2778`, `svm.rs:2931`, `apply.rs:783-787` |
| G2 | `model_id` unbound to any governed namespace; anyone registers any model | **High** for consumers | `zkml.rs:1633-1647` |
| G3 | No input/context binding (no chain id, height, sender, request) → proofs are bearer tokens | Medium today, **High** for the future seam | `zkml_attestation.rs:409-423` |
| G4 | Registration state is permanent, uncapped in total, and re-hashed on every registry change | **High** DoS (see §2) | `commitment.rs:1575-1598`, `mempool.rs:2842-2852` |
| G5 | `verify_attestation` public helper does not bind `spec_bytes` to `proof.model_hash` | Medium (API footgun) | `zkml_attestation.rs:445-556` |
| G6 | `verify_inference` (unsound) is still `pub`; a direct caller gets `true` on forgery | Medium (API footgun) | `zkml.rs:1495-1558` |
| G7 | Reexec proof bytes have **no** size cap (attestation has 65,536) | Low/Medium | `zkml.rs:1294-1300`, `zkml_attestation.rs:105` |
| G8 | `ZkMlModelRecord` doc says "in-memory only ... no persisted encoding" — **false** | **High** for the seam | `zkml.rs:1583-1585` vs `storage.rs:1241-1252`, `accounts.rs:2184-2188` |

**G8 detail (this one will bite whoever implements the seam).** The registry is
persisted as `bincode(ZkMlModelRegistry)` into a sled tree
(`storage.rs:1241-1252`, opened at `storage.rs:434`), restored through
`bincode_deserialize_limited` (`accounts.rs:2184-2188`) which sets
`allow_trailing_bytes()` (`types.rs:87-96`). Consequences:

- adding a trailing field to `ZkMlModelRecord` / `ModelSpec` makes **old**
  binaries silently accept new bytes and ignore the tail (no error, different
  digest ⇒ silent consensus divergence);
- **new** binaries fail to restore old snapshots (bincode cannot default a
  missing positional field).

The comment at `zkml.rs:1583-1585` invites exactly that change. It is wrong and
must be corrected before anyone adds a field. Use a *separate* registry /
conditional domain instead (§3).

---

## 2. Cost model: gas charged vs. CPU actually spent

### 2.1 The numbers

Constants: `GAS_ZKML_VERIFY_IN=5_000`, `GAS_ZKML_PROOF_PER_BYTE=2`,
`GAS_ZKML_REEXEC_PER_PARAM=1`, `GAS_ZKML_REGISTER=1_000`,
`GAS_ZKML_REGISTER_PER_PARAM=4` (`svm.rs:178-199`);
`GAS_ATTESTATION_VERIFY_BASE=30_000`,
`GAS_ATTESTATION_PER_PUBLIC_INPUT=200`,
`GAS_ZKML_SPEC_REGISTER_BASE=2_000`, `GAS_ZKML_SPEC_PER_BYTE=4` (`svm.rs:258-269`).

Let `P` = `param_count()` (weights + biases, `zkml.rs:1191-1196`), `B` =
`proof_bytes.len()`, `I`/`O` = public input/output counts.
`wire_len = B + 8(I+O) + 32` for `ZkMlProof` (`zkml.rs:1294-1300`) and
`B + 8(I+O) + 64` for `AttestationProof` (`zkml_attestation.rs:141-147`).

| Opcode | Gas formula | Max with current caps |
|---|---|---|
| Reexec | `5_000 + 2·wire_len + P` | `P≤16_384`; `I,O` uncapped by code (bounded in practice by `in_dim/out_dim`); `B` only bounded by the 24 MiB block wire cap (`mempool.rs:779`) |
| Attestation | `30_000 + 200(I+O) + 2·wire_len + P` | `P≤16_384`, `I,O≤128` (constrained format `zkml_attestation.rs:90-107`), `B≤65_536` ⇒ **≈233k gas** |

Max per-call CPU work for both paths: `P` MACs (`zkml.rs:1132-1147`), plus, for
attestation, an O(P) `check_compatible` pass (`zkml_attestation.rs:180-250`) and
an O(P) BLAKE3 Merkle rebuild (`zkml_attestation.rs:492-528`); plus, for
reexecution, a SHA-256 per layer for `compute_model_hash` (`zkml.rs:1198-1205`,
`zkml.rs:1079-1090`) and **two** bincode decodes of `B` bytes (`zkml.rs:1467`,
`zkml.rs:1500`).

### 2.2 The pricing inversion (static, verifiable)

- One model MAC is charged **1 gas** (`svm.rs:191`, `svm.rs:2760-2761`).
- One VM `Mul` is charged **10 gas** (`svm.rs:209`, `svm.rs:1455-1457`).
- The admission floor for any transaction is **280_000 gas**
  (`mempool.rs:1394`, `svm.rs:38`).

So re-executing a whole 16,384-parameter model (`5,064 + P + 2B ≈ 21.5k gas`)
costs **~7.7% of the price of a bare transfer** while doing 16,384
multiply-accumulates. Per unit of arithmetic the chain prices zkML work **10×
below** an ordinary `Mul` opcode.

### 2.3 Can an attacker force expensive work cheaply? Yes, three ways

**(a) Layer-bomb model — cheap per-model, not per-param.** The price is linear
in `P` but several costs are linear in the **layer count** `L`: one SHA-256
(`compute_model_hash`), one `Vec` allocation (`forward`), and one bincode struct
per layer. The reexecution path does **not** cap layers
(`zkml.rs:1169-1186` and `zkml.rs:1648-1679` cap only `P`); attestation caps
`L≤8` (`zkml_attestation.rs:102`). A model of `L = 8_192` layers of `1×1`
(1 weight + 1 bias each) has `P = 16_384` and costs **16,384 gas** but forces
8,192 SHA-256 compressions + 8,192 allocations + 8,192 loop iterations per
verify. That is ~0.5 hash + 0.5 alloc per gas unit, versus ~1 MAC per gas unit
for a dense model — a 50–100× CPU-per-gas difference (operation counts are
exact from the code; wall-clock **UNVERIFIED**, no benchmark was run).

**(b) Proof-byte parsing is charged at 2 gas/byte but paid 2–3 times.**
`B` is deserialized twice in `verify_inference_against` (`zkml.rs:1467`,
`zkml.rs:1500`) and iterated once more for the FS hash (`zkml.rs:1518-1523`).
The reexecution path has **no per-proof cap** (`zkml.rs:1294-1300`), unlike
attestation's `MAX_ATTESTATION_PROOF_BYTES = 65_536`
(`zkml_attestation.rs:105`, enforced at `zkml_attestation.rs:461`). A 24 MiB
proof (block wire cap, `mempool.rs:779`) costs ~50M gas and is parsed twice;
it is then rejected on `traces.len()` mismatch (`zkml.rs:1470`).

**(c) Registration is not a "proof unit" and never expires.** This is the
strongest one.

- `count_tx_proof_units` counts only the two verify opcodes (16 and 64 units);
  registrations count **0** (`mempool.rs:2842-2852`).
- The per-block proof cap is 2,048 units (`mempool.rs:784`), so reexecution is
  bounded at **128 verifies/block**, attestation at **32/block**. Combined with
  the 16,384-param cap that is ≤2.1M MACs/block — bounded and survivable.
- **Registrations have no such cap.** They cost `1_000 + 4·P`
  (`svm.rs:228-231`), i.e. **65,536 gas for a 128 KiB model** — a quarter of
  the transfer floor. Each is permanent state: there is no deregistration, no
  expiry, no rent, and `prune_zkml_models_below` prunes only old *height
  snapshots*, not live state (`storage.rs:1259-1276`).
- Every registration bumps `Domain::Zkml`, so the next commitment recompute
  rebuilds the preimage of the **entire** registry — every weight of every
  model — and caches it as a second full copy of the bytes
  (`commitment.rs:1575-1598`, cache at `accounts.rs:856-872`). One cheap
  registration per block therefore makes the *whole accumulated registry* get
  re-serialised and re-hashed on that block.
- Wire arithmetic: each parameter is an `i64` on the wire, so 24 MiB/block ⇒
  ~3.1M params (~24 MiB of model bytes) of permanent growth per block, for
  ~192 max-size registrations × 280k admission floor ≈ 54M gas (~11% of
  `MAX_BLOCK_GAS`; the 24 MiB wire cap binds long before block gas does — the
  4 gas/param charge is only ~12.8M for the same set).
  The resulting per-block hashing cost is **O(total registered weights)** and
  grows without bound; total cost is quadratic in blocks. Memory doubles
  (registry `i64`s + cached preimage).

### 2.4 Current caps (complete list)

| Cap | Value | Site |
|---|---|---|
| Params per model | 16,384 | `zkml.rs:1056`, enforced `zkml.rs:1663-1668` |
| Layers / dims (attestation only) | 8 / 128 | `zkml_attestation.rs:101-102` |
| Public I/O (attestation) | 1,024 | `zkml_attestation.rs:103` |
| Attestation proof bytes | 65,536 | `zkml_attestation.rs:105`, `:461` |
| Model spec bytes / setup label | 65,536 / 1,024 | `zkml_attestation.rs:106-107` |
| Proof units per block | 2,048 (16/64 per op) | `mempool.rs:784`, `:2842-2852` |
| Block gas / block txs / block wire | 500M / 10,000 / 24 MiB | `runtime/mod.rs:239`, `:215`, `mempool.rs:779` |
| Admission gas floor | 280,000 | `mempool.rs:1394` |
| **Total registry size / model count / registrations per block** | **none** | — |
| **Reexecution proof bytes** | **none** | `zkml.rs:1294-1300` |

Note that the *fee* is the **declared** `gas_limit`, not the gas consumed
(`svm.rs:47-49`), so over-declaring is the only way a sender ever pays more
than the table; under-declaring causes a cheap fail before the work runs
(`svm.rs:2762-2765`, `svm.rs:2920-2923`). The DoS analysis above is therefore
about *state and packing*, not about fee evasion.

---

## 3. The seam

### 3.1 Design constraints (non-negotiable)

1. **Wire format is frozen.** `Transaction`/`Block` gain no fields (bincode 1.3
   is positional; see `zkml.rs:266-272`). Existing opcode encodings and
   discriminants 35–38 stay byte-identical (pinned by
   `tests/zkml_live_tests.rs:762` and `tests/zkml_attestation_tests.rs:1333`).
2. **No new persisted field on `ZkMlModelRecord` or `ModelSpec`** — see G8
   above. The persisted blob decodes with `allow_trailing_bytes`
   (`types.rs:87-96`), so a trailing field is a *silent* fork between binary
   versions.
3. **Behaviour today is byte-identical**, including gas, verdicts and the
   state root.
4. Consensus gates must be **committed or frozen constants**. A node-local env
   gate that changes acceptance is a chain split; `STELL_CHAIN_ID` is already a
   deployment setting, not a consensus one (`zkml.rs:186-211`).
5. A new proof system may only be selected by data that is **already
   committed**. The one such field that exists today is
   `ModelSpec.setup_attestation`, which is committed in
   `write_zkml_vks_domain` (`commitment.rs:1624-1644`, specifically `:1642`).

### 3.2 New module (Stage 0: plumbing only, zero behaviour delta)

Create `stellereum/src/zkml_verify.rs`:

```rust
use crate::zkml::{ZkMlModelRecord, ZkMlProof};
use crate::zkml_attestation::{AttestationProof, ModelSpec};

/// Which verification algorithm the node is allowed to run. `Reexec` is the
/// only variant that may exist before an activation gate opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSystem {
    /// Today: run the model. Sound, linear, not succinct.
    Reexec,
    // Reserved, NOT implemented, NOT shippable until audited:
    // Groth16Bn254, StarkBlake3, HybridDigest,
}

impl ProofSystem {
    /// The committed selector. Empty / unknown => Reexec (today's behaviour).
    /// Recognised prefixes are only read when `ZkMlVerifyPolicy::is_active`.
    pub fn from_setup_label(label: &[u8]) -> Option<Self>;

    /// The canonical label prefix for this system (empty for Reexec).
    pub const fn label_prefix(self) -> &'static [u8];
}

/// The gate. Default == today, and must remain the default in every build.
#[derive(Clone, Copy, Debug)]
pub struct ZkMlVerifyPolicy {
    pub system: ProofSystem,
    /// Hard-fork height. `u64::MAX` = disabled: the label is ignored and
    /// `system` is forced to `Reexec`. Set only by a spec change.
    pub activation_height: u64,
    /// Largest model the HYBRID fallback may re-execute. Irrelevant for
    /// `Reexec` (already bounded by MAX_ZKML_MODEL_PARAMS).
    pub max_fallback_params: usize,
}

impl Default for ZkMlVerifyPolicy {
    fn default() -> Self {
        Self {
            system: ProofSystem::Reexec,
            activation_height: u64::MAX,
            max_fallback_params: crate::zkml::MAX_ZKML_MODEL_PARAMS,
        }
    }
}

impl ZkMlVerifyPolicy {
    pub fn is_active(&self, height: u64) -> bool { height >= self.activation_height }

    /// The system actually used for this call. Deterministic: a function of
    /// (policy, height, committed label) only.
    pub fn resolve(&self, height: u64, rec: &ZkMlModelRecord) -> ProofSystem;
}

/// Pre-charged budget, so a verifier can never spend more than it paid for.
pub struct VerifyBudget { pub gas_remaining: u64, pub gas_used: u64 }

pub enum VerifyError {
    UnknownModel,
    ModelHashMismatch,
    NoSpec,
    SpecHashMismatch,
    ShapeMismatch,
    InputDomain,
    ProofInvalid,
    UnsupportedProofSystem,
    OutOfGas,
}

/// What a verifier RETURNS. Callers must never trust the proof's own
/// `public_outputs`; they use this value.
pub struct VerifiedInference {
    pub model_id: [u8; 32],
    pub model_hash: [u8; 32],
    pub inputs: Vec<u64>,
    pub outputs: Vec<u64>,
}

/// Borrowed, non-owning view over EITHER opcode's proof payload.
///
/// This is the only shape the verifier sees. Neither `ZkMlProof` nor
/// `AttestationProof` is redefined, so the wire format is untouched; the two
/// `From` impls are field copies, not re-encodings.
pub struct ProofView<'a> {
    pub model_hash: [u8; 32],
    /// `None` for `SysCallVerifyZkMlReexec` (no spec is involved).
    pub spec_hash: Option<[u8; 32]>,
    pub public_inputs: &'a [u64],
    pub public_outputs: &'a [u64],
    pub proof_bytes: &'a [u8],
}

impl<'a> From<&'a ZkMlProof> for ProofView<'a> {
    fn from(p: &'a ZkMlProof) -> Self {
        Self {
            model_hash: p.model_hash,
            spec_hash: None,
            public_inputs: &p.public_inputs,
            public_outputs: &p.public_outputs,
            proof_bytes: &p.proof_bytes,
        }
    }
}

impl<'a> From<&'a AttestationProof> for ProofView<'a> {
    fn from(p: &'a AttestationProof) -> Self {
        Self {
            model_hash: p.model_hash,
            spec_hash: Some(p.spec_hash),
            public_inputs: &p.public_inputs,
            public_outputs: &p.public_outputs,
            proof_bytes: &p.proof_bytes,
        }
    }
}

pub trait InferenceVerifier {
    fn system(&self) -> ProofSystem;
    /// Work the handler must charge BEFORE calling `verify`.
    fn precharge(&self, rec: &ZkMlModelRecord, proof_wire_len: usize) -> u64;
    /// MUST recompute `model_hash` from `rec.model`; MUST NOT read it from
    /// the proof. MUST be deterministic and side-effect free.
    fn verify(
        &self,
        model_id: [u8; 32],
        rec: &ZkMlModelRecord,
        spec: Option<&ModelSpec>,
        proof: ProofView<'_>,
        budget: &mut VerifyBudget,
    ) -> Result<VerifiedInference, VerifyError>;
}

pub struct ReexecVerifier; // thin wrapper over today's code
```

`ReexecVerifier::verify` must be a **literal** call to the existing functions —
`crate::zkml::ZkMlProof::verify_inference_against` for the reexecution shape and
`crate::zkml_attestation::verify_attestation` for the spec shape — plus the two
hash checks currently inlined in the handlers (`svm.rs:2751`, `svm.rs:2864`,
`svm.rs:2877`, `svm.rs:2883-2890`, `svm.rs:2894-2902`). Move, do not rewrite.

Single entry point used by the VM:

```rust
pub fn verify_inference(
    policy: &ZkMlVerifyPolicy,
    height: u64,
    model_id: [u8; 32],
    rec: &ZkMlModelRecord,
    proof: ProofView<'_>,
    budget: &mut VerifyBudget,
) -> Result<VerifiedInference, VerifyError>;
```

### 3.3 Exact call sites to thread the policy through

| # | Site | Change |
|---|---|---|
| 1 | `svm.rs:1345-1351` `Svm::execute_inner` | add `policy: &ZkMlVerifyPolicy, height: u64` |
| 2 | `svm.rs:1335-1343` `Svm::execute_with_confidential_and_sends` | add the same two params |
| 3 | `svm.rs:1308-1314` `Svm::execute` | add the same two params (or pass `&Default::default(), 0`) |
| 4 | `state_engine/apply.rs:721-727` (block path) | pass `&self.zkml_verify_policy, height` |
| 5 | `state_engine/apply.rs:3598-3604` (delivered actor body) | pass the engine policy; registry is `None` so the opcodes revert regardless (`apply.rs:3594-3597`) |
| 6 | `svm.rs:2734-2779` (Reexec handler) | replace bodies 2735-2778 with `budget`-based call to `verify_inference` |
| 7 | `svm.rs:2837-2931` (Attestation handler) | same; note the existing pre-checks (2861-2902) move into the verifier |
| 8 | `svm.rs:2799-2836` (spec registration) | parse + validate the system label under the gate; reject `UnsupportedProofSystem` **only when active** |
| 9 | `zkml.rs:96` `zkml_capabilities` | see §5 |
| 10 | `zkml.rs:1224-1235` `is_attestation_compatible` | no change for Reexec; the hybrid may need a stricter predicate later |

**Do not change `opcode_gas` (`svm.rs:333-443`).** The wire-visible part
(`5_000 + 2·wire_len`, `30_000 + 200·(I+O) + 2·wire_len`) stays exactly as is,
so block packing is unchanged. Any per-system surcharge is charged in-handler
from `InferenceVerifier::precharge`, exactly like today's `GAS_ZKML_REEXEC_PER_PARAM`
(`svm.rs:2760-2765`, `svm.rs:2918-2923`). This is what keeps the mempool's
price estimate (`mempool.rs:1946-1995`) and the apply-time charge in agreement.

**No change to `VmContext`.** `zkml_models` is already a parameter
(`svm.rs:1340`); the policy follows the same route. That avoids touching every
`VmContext` literal (e.g. `apply.rs:652-711`, `apply.rs:3573-3593`).

### 3.4 Where the real proof lives (Stage 1, still no wire change)

The only place a new proof can ride without a wire change is the **opaque,
already-carried, already-priced** `AttestationProof.proof_bytes`
(`zkml_attestation.rs:137`, capped at `:461`, priced at `svm.rs:278`). The
selector is the committed `setup_attestation` label. Therefore:

```text
proof_bytes := <new system's canonical encoding>       (opaque to old nodes)
label       := b"PROOF-SYSTEM:<name>:<version>:<params>"  (committed, commitment.rs:1642)
```

Rules that make this safe:

- `resolve()` returns `Reexec` unless `is_active(height)` **and** the label
  parses **and** the model was registered after activation. Pre-activation
  proofs keep verifying under the old path forever.
- The new verifier's FS/challenge domain must be **new**
  (e.g. `STELL_PQ_INFERENCE_V2`) and must include
  `chain_id || model_id || model_hash || spec_hash || setup_label || inputs ||
  outputs`. This is a **gated** acceptance change (old proofs stop verifying
  once the label is active) and therefore a hard fork, not a hotfix.
- The verifier must recompute `model_hash` from `rec.model` and compare, never
  trust `proof.model_hash`. Same for the spec: recompute
  `spec_hash_of(spec_bytes)` (`zkml_attestation.rs:150-154`) before use.
- The new verifier must return `VerifiedInference`; the handler must compare
  *that* against the stack/consumer, never `proof.public_outputs`.
- If a succinct system is unavailable or the proof is malformed, the **only**
  allowed fallback is `Reexec`, and only when
  `param_count <= max_fallback_params`; otherwise revert
  `UnsupportedProofSystem`. Silent fallback must be impossible — a validator
  that falls back while another accepts would fork.

**Explicit non-goal:** Stage 0 adds **no** security. It is plumbing so that a
future audited proof system is a single trait implementation plus a gate
constant. No SNARK/STARK should ship on the strength of this seam; it needs a
circuit, a commitment scheme, a soundness argument, a decision about trusted
setup (the current subsystem has none, and `trusted_setup: false` at
`zkml.rs:109` must stay false until a ceremony actually exists), a gas
recalibration, a spec update, and an external audit.

**Limitation of the zero-wire option (state it now, not later):** the label
lives in `ModelSpec`, so it can only select a proof system for
`SysCallVerifyZkMlAttestation`. `SysCallVerifyZkMlReexec` never reads a spec
(`svm.rs:2734-2779`) and therefore has **no committed selector at all** in the
current state. Either (a) a real system is attestation-only, or (b) the
reexecution path needs the separate `ZkMlProofPolicyRegistry` of §3.5 (an
additive hard fork). Do not "solve" this by putting the selector in the proof
itself: the prover would then choose whether its own proof is checked by
re-execution, which is a free bypass.

### 3.5 The one state change that *is* safe

If a per-model policy map is preferred over the label, add **a separate
conditional domain** following the existing pattern:

```rust
// commitment.rs, new fn
pub fn write_zkml_proof_policy_domain<S: PreimageSink>(h: &mut S, reg: &ZkMlProofPolicyRegistry) {
    if reg.is_empty() { return; }          // empty => zero bytes => genesis root unchanged
    put_bytes(h, b"zkml_proof_policy_domain", b"ZKML_PROOF_POLICY_V1");
    ...
}
```

called after `write_zkml_vks_domain` (`commitment.rs:1906`, `:2140-2141`),
plus a new **appended** opcode at the end of the enum. This is an additive wire
extension (a hard fork), but it never changes an existing discriminant and never
changes an existing persisted struct. Prefer the label for Stage 0 because it
needs neither.

---

## 4. Test plan for the future change

Everything below must be green **before** a gate is allowed to open. Group A
must also land with Stage 0 (they prove Stage 0 changed nothing).

### A. Differential: the seam must be a no-op today

1. For a corpus of {honest proof, forged structural proof, wrong-model proof,
   truncated proof, oversized proof}, `ReexecVerifier` returns the same verdict
   and the same `gas_used` as the current handlers. Sources:
   `zkml.rs:1812-1868`, `tests/zkml_live_tests.rs:152-220`,
   `tests/zkml_attestation_tests.rs:261-393`.
2. `opcode_gas(op)` is unchanged for discriminants 35/36/37/38
   (`tests/zkml_live_tests.rs:493-544`,
   `tests/zkml_attestation_tests.rs:998-1043`).
3. `commitment_digest` with an empty registry equals the pre-change base, and
   `COMMITMENT_VERSION` does not move (`tests/zkml_live_tests.rs:899-968`,
   `tests/zkml_attestation_tests.rs:1444`).
4. Restore a registry snapshot produced by the **old** binary and assert it
   decodes and yields an identical state root (`accounts.rs:2184-2188`).
   Then assert the **reverse** direction fails loudly (old decoder must not
   silently accept a new field) — this is the G8 regression.

### B. Model/output substitution (the core soundness pins)

5. **Wrong model:** honest proof for model A submitted under `model_id` B whose
   record has different weights ⇒ revert. (Exists: `tests/zkml_live_tests.rs:234`;
   extend to every verifier.)
6. **Wrong output:** flip one entry of `public_outputs` ⇒ revert, for both
   opcodes and for the new verifier.
7. **Wrong input:** change one `public_inputs` entry but keep outputs ⇒ revert.
8. **Swapped `model_hash`:** a valid underlying proof with `model_hash` edited ⇒
   revert. This pins "the verifier recomputes, never trusts".
9. **Swapped `spec_hash` / wrong spec:** register spec for A, submit a proof
   claiming B's spec hash under A ⇒ revert (`svm.rs:2877`). Plus: a spec whose
   `spec_bytes` deserialise to a different model is refused at registration
   (`zkml_attestation.rs:570-584`).
10. **Dead-field malleability:** mutate only `query_samples` / a second
    `commitments` entry. The new verifier must reject non-canonical encodings
    (assert the verdict flips to reject), so an attacker can never garnish an
    accepted proof.
11. **Label confusion:** a model with a non-empty, unparsable label must
    resolve to `Reexec` and behave exactly as before; a model with a
    recognised label but an inactive gate must also resolve to `Reexec`.

### C. Replay / context binding (new, must be added by the real system)

12. Same proof, different chain id ⇒ reject.
13. Same proof, different `model_id` with identical weights ⇒ reject (bind
    `model_id` into the transcript, not just `model_hash`).
14. Same proof, different height/sender/request nonce ⇒ reject (the statement
    the chain accepts must include the context it is accepted in).
15. Cross-opcode: a proof accepted by Attestation must not be silently
    accepted by Reexec with weaker input-domain rules (assert the two verifiers
    agree on domain checks, or that they refuse each other's statements).

### D. Cost / DoS

16. Static operation-count assertions (no wall clock):
    a `L=8_192 × 1×1` layer-bomb must be charged at least as much as a dense
    `128×128` model of the same `P`, or be rejected outright. Today it is not
    (`zkml.rs:1191-1196` prices only `P`).
17. A max-size proof (`24 MiB`) must not be accepted at a gas price below its
    parse cost; pin that the reexecution path has a byte cap (G7).
18. Registering `N` models then registering one more must not make the
    commitment recompute super-linear in `N` without a matching charge; at
    minimum pin that a block's worth of registrations is bounded (currently it
    is not — `mempool.rs:2842-2852` counts 0 units for registration).
19. `precharge` for a hybrid/succinct system must be **≥** the reexecution
    price whenever the fallback can trigger, so a caller cannot buy a fallback
    re-execution at a succinct price.

### E. Capability truth

20. Extend `capability_statement_is_honest_and_machine_readable`
    (`zkml.rs:1747-1801`): while no proof system is active, still assert
    `zero_knowledge == false`, `succinct == false`, `hiding == false`,
    `trusted_setup == false`. Add an assertion that the new
    "result observability" / "model selection" fields say the truth (§5).
21. Two independent engines with byte-identical registries must accept/reject
    identically (extend `tests/zkml_live_tests.rs:339`,
    `tests/zkml_attestation_tests.rs:1111`).

### F. Regression that must never be relaxed

22. `forged_proof_passes_structural_but_fails_sound_check`
    (`zkml.rs:1822-1868`) and `forged_proof_is_rejected_on_the_live_block_path`
    (`tests/zkml_live_tests.rs:177-219`) stay green. If a future verifier makes
    them fail "because we now have a real proof system", the test is wrong and
    has been weakened — treat that as a review blocker.

---

## 5. Honest product wording

### 5.1 What is already honest (and should stay)

- `zkml_capabilities()`: `zero_knowledge=false`, `succinct=false`,
  `hiding=false`, `trusted_setup=false`, `sound=true`
  (`zkml.rs:96-147`), served at `rpc/reads.rs:2161-2166`, exposed as a public
  method in `rpc/streams.rs:1232` and asserted there in `rpc/tests.rs:8817`.
- Module headers (`zkml.rs:6-15`, `zkml_attestation.rs:1-81`) and opcode docs
  (`svm.rs:679-705`, `svm.rs:777-804`) say "re-execution, not ZK".
- `docs/specs/03_VM_AND_EXECUTION_PHASE2.md:17` correctly prices zkML-verify at
  5,000; `docs/site/06-security.md:54` records KI-31/33.

### 5.2 Strings that still say STARK/ZK (post-wave status)

The earlier overclaims were corrected as **text only** in module headers,
doc comments, the RPC capability statement and `docs/CODE_INDEX.md`; the
mechanism was not changed. The remaining occurrences are deliberate legacy
names or error tags, not claims:

| Where | String | Status |
|---|---|---|
| `zkml_attestation.rs:125` | `ZKML_ATTESTATION_PROTOCOL_TAG = b"STELLEREUM_PQ_STARK_BLAKE3_V1"` | **Remains.** A committed Fiat–Shamir preimage; changing it changes every transcript (hard fork). Its doc says it is a legacy name and the mechanism is re-execution with a BLAKE3 Merkle trace root. |
| `zkml_attestation.rs` | `"stark: ..."` error strings (`validate`, proof decode, spec checks) | **Remains.** Internal error prefixes; no proof-system claim. Rename only with a compatible error-contract change. |
| `docs/specs/02_CRYPTO_AND_PQ.md` | `STELLEREUM_PQ_STARK_BLAKE3_V1` | Kept as the honest legacy-tag note: NOT a STARK, NOT a SNARK, verifier re-executes. |
| `docs/CODE_INDEX.md` | "legacy protocol tag ... not a STARK" | Fixed to state the limitation explicitly. |
| `zkml.rs:1421-1422`, `zkml_attestation.rs:40-41` | "what makes a value-bearing decision sound" | Already qualified: the chain has no branch/event/stored return value, so a verify is an EVENT, not a gate. |

Remaining semantic caveat (unchanged): the chain cannot act on a zkML verdict
in-transaction (G1), and re-registering the byte-identical model is now an
idempotent no-op (different weights under a taken id still revert).

### 5.3 Fields the capability statement should add (RPC-only, JSON — safe)

`ZkMlCapabilities` is serialised only over JSON (`rpc/reads.rs:2161`); it is
never bincode-persisted. Adding `#[serde(default)]` fields is therefore wire-safe
and old clients keep working.

```rust
/// Who may bind a model_id to a model. Today: anyone.
pub model_selection: String,        // "permissionless (no allowlist, no governed namespace)"
/// Can an on-chain program act on the verdict? Today: no.
pub result_consumption: String,     // "none: tx success/failure only; no event, no state, no branch"
/// What the proof's inputs are bound to. Today: only themselves.
pub input_binding: String,          // "none: prover-chosen; no chain id, height, sender or request id"
/// Plain-language warning for integrators.
pub integration_warning: String,    // "Do not treat a successful verify as a trustworthy
                                    //  decision unless YOU pin model_id, the weights, the
                                    //  inputs, and re-derive them from the block yourself."
pub proof_systems: Vec<ProofSystemCapability>, // [{system:"reexec", succinct:false, gated_at:null}]
```

And two corrections to existing text:

- `trusted_setup: "the committed model registry (append-only, hash-matched)"`
  (`zkml.rs:124`) reads as "vetted". It is not. Either rename the field to
  `premise` / `assumption`, or say
  `"you must pin the model_id you trust; anyone can register any model"`.
- `setup_note` (`zkml.rs:110-114`) is accurate but only mentions the label;
  add that the label is **unauthenticated and first-writer-wins**, so a
  registry entry can carry someone else's label (`zkml.rs:1709-1715`).

### 5.4 Suggested one-liner for docs and RPC

> Stellereum's zkML is **verifiable inference by re-execution**. A successful
> `SysCallVerifyZkMlReexec` / `SysCallVerifyZkMlAttestation` proves that the
> outputs are the deterministic integer forward pass of the model registered
> under the named `model_id`, on the inputs carried in the proof. It is sound,
> but it is **not zero-knowledge, not succinct, and not hiding**: every node
> runs the model, and the inputs and outputs are public. Model registration is
> permissionless, so a verify is only meaningful if **you** pin the `model_id`
> and the weights. The chain records the verdict as transaction success only —
> no event, no state, and no on-chain consumer can branch on it.

---

## Appendix — how each claim was checked

```bash
grep -n "SysCallVerifyZkMl" stellereum/src/svm.rs
grep -n "zkml" stellereum/src/state_engine/apply.rs
grep -n "zkml_models" stellereum/src/commitment.rs
grep -rn "zkml_models" stellereum/src/storage.rs stellereum/src/state_engine/accounts.rs
grep -n "count_tx_proof_units" -A 12 stellereum/src/mempool.rs
grep -n "MAX_BLOCK_GAS\|MAX_BLOCK_TXS" stellereum/src/runtime/mod.rs
sed -n '1435,1560p;1616,1735p' stellereum/src/zkml.rs
sed -n '445,556p' stellereum/src/zkml_attestation.rs
```

No `cargo` gate was run for this audit (read-only task); all cost statements are
**static operation counts** derived from the cited lines, not wall-clock
measurements. Any timing claim in this document would be UNVERIFIED — and note
that the existing bench (`stellereum/benches/zkml_attestation.rs:52-72`)
measures `verify_inference`, i.e. the **unsound structural check**, not the
live re-execution path.

---

## Appendix 2 — Remediation status (2026-11-18, same tree)

Status: the small, consensus-safe fixes from this audit have landed. No proof
system was added; no opcode, wire byte or committed preimage changed.

| Finding | Status | Where |
|---|---|---|
| False "PQ STARK" strings / comments | **Fixed as text only.** `ZKML_ATTESTATION_PROTOCOL_TAG` bytes and the tag name are UNCHANGED (committed FS preimage); the definition now states it is a legacy name and the mechanism is re-execution. Prover/verifier section headers, `AttestationProof` doc, "setup" wording and the "cryptographic soundness" comment corrected. | `zkml_attestation.rs`, `svm.rs` |
| "would fail the pairing check" | **Fixed.** No pairing exists; the u16 gate is a range check ahead of re-execution. | `svm.rs` |
| `trusted_setup` reads as "vetted" | **Fixed.** The JSON field name is kept for RPC compatibility; its doc and values now say `PREMISE`, and `setup_note` states there is NO setup and the label is unauthenticated + first-writer-wins. | `zkml.rs::zkml_capabilities` |
| Registration DoS (0 proof units, no total cap, full-preimage rebuild) | **Partially fixed, bounded.** Registration now costs proof units; the registry has total model/parameter caps; an identical duplicate registration is an idempotent no-op. | see constants below |
| Context binding | **Opt-in seam only, inert.** New bound transcript + gate; default behaviour byte-identical. | `zkml_attestation.rs` |
| G8 persisted-registry comment | **Fixed.** The comment now says the registry IS bincode-persisted with trailing-byte tolerance, so a new field is a silent cross-version fork. | `zkml.rs::ZkMlModelRecord` |
| `return_value` dropped | **Documented, semantics unchanged.** A zkML verify is an EVENT, not a branch condition. | `svm.rs` opcode docs, `zkml.rs`, `apply.rs` is untouched |

New constants (all deterministic, committed-or-frozen):

- `zkml::MAX_ZKML_REGISTRY_MODELS = 4_096` — total registry cap (refusal:
  `"registry full: ..."` → transaction revert, no state change).
- `zkml::MAX_ZKML_REGISTRY_PARAMS = 1_048_576` — total parameters across all
  models (8 MiB of `i64` weights; 64 max-size models). Computed by summing live
  records, so NO new persisted field.
- `mempool::PROOF_UNITS_REGISTER_MODEL = 16`,
  `mempool::REGISTER_PARAMS_PER_PROOF_UNIT = 1024`,
  `mempool::PROOF_UNITS_REGISTER_SPEC = 16` — a max-size registration costs 32
  units, so at most 64 fit the existing `MAX_BLOCK_PROOF_UNITS = 2048` budget.
- `zkml_attestation::ZKML_ATTESTATION_CONTEXT_TAG =
  b"STELLEREUM_INFERENCE_CTX_V1"` — NEW FS domain, used only by the opt-in
  bound prover/verifier.
- `zkml_attestation::ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT = u64::MAX` — the
  gate; `u64::MAX` means never. A `cfg(test)`-only, thread-local override exists
  so tests can open it; no release build has a gate knob.

Binding content (when/if the gate ever opens): `chain_id || model_id ||
height || sender`, in a distinct domain, so a bound proof is not a bearer token
and does not verify against the legacy transcript (and vice versa).

What a verify still CANNOT do (unchanged, deliberate): the VM has no branch,
`apply.rs` drops `VmExecutionResult::Success.return_value`, and no event/state
records the verdict. A verify is an **event** (transaction success/failure), not
a **branch condition**; any value-bearing decision must be taken off chain from
the public payload. `SysCallVerifyZkMlReexec` / `SysCallVerifyZkMlAttestation`
remain unobservable to on-chain programs.

Still open (unchanged by this wave): G1 (no on-chain consumer), G2 (model
selection permissionless), G5/G6 (public helper footguns), G7 (no reexecution
proof-byte cap), the layer-count pricing inversion, and any real proof system.
