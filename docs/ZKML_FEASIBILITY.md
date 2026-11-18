# zkML feasibility for Stellereum — which proof system, if any, fits a block

Status: research note, 2026-11-18. Read-only study; no code changed.
Every number is either (a) measured in this repo, (b) taken from a cited
external benchmark, or (c) marked **ESTIMATE** / **UNVERIFIED** with the
arithmetic that produced it.

---

## 0. What the chain actually has today (verified in code)

| Fact | Value | Source |
|---|---|---|
| What "zkML" is | verifiable inference **by re-execution** | `stellereum/src/zkml.rs:6-15` |
| Machine-readable claim | `zero_knowledge:false`, `succinct:false`, `hiding:false`, `sound:true`, `trusted_setup:false` | `zkml.rs:96-147` |
| Model cap | 16,384 `i64` parameters | `zkml.rs:1056` |
| Shape caps | ≤ 8 layers, each dim ≤ 128 | `zkml_attestation.rs:101-102` |
| Weight/input format | i8 weights, u16 inputs, i32 accumulators, ReLU | `zkml_attestation.rs:92-102` |
| Verifier work | re-runs the forward pass, linear in params | `zkml.rs:1435-1479` |
| Block gas cap | 500,000,000 | `runtime/mod.rs:239` |
| Basic transfer gas | 280,000 ⇒ ~1,785 transfers/block | `svm.rs:38`, `runtime/mod.rs:230-239` |
| Block wire cap | 24 MiB | `mempool.rs:779` |
| Proof-unit cap | 2,048 per block, **because verify serializes on the apply worker** | `mempool.rs:780-786` |
| Gas for one re-exec verify | 5,000 + 2/byte + 1/param | `svm.rs:162-224` |

The comment on `MAX_BLOCK_PROOF_UNITS` is the single most important sentence in
the codebase for this question: *"attestation verifies and zkML re-executions
serialize on the single apply worker … gas alone does not [bound it] (cheap gas,
costly verify)."* Any proof system added here inherits that serialization.

### 0.1 Budget, measured, not assumed

| Measurement | Value | Source |
|---|---|---|
| apply, 1000 mixed tx | **20.348 ms** (49,145 tx/s) | `docs/PERF_PROFILE.md:59` |
| apply, 428 mixed tx | 12.604 ms | `docs/PERF_PROFILE.md:58` |
| full 1,785-tx block (gas-capped) | ~35 ms apply | `runtime/mod.rs:230-237` |
| whole per-height CPU at 428 tx | ~23.6 ms | `docs/PERF_PROFILE.md:111-121` |
| live block cadence | ~2–3 s sustained, p50 bursts ~0.5 s | `docs/BFT_COMPARISON.md:35` |

**Correction to the brief.** The brief says "apply 1000 tx ≈ 3.2 ms". That number
is not in the repo; the measured value is 20.348 ms. If 3.2 ms is real for a
different workload, multiply every "gas per ms" figure below by ~6 — the
conclusions do not change, they get stronger.

From 500M gas ↔ ~35 ms of apply CPU: **1 ms of block CPU ≈ 14.3M gas**, or
14,300 gas per microsecond. Stated the other way: the entire execution budget of
a *gas-full* block is ~36 ms on one core.

So the brief's "20 ms for extra verification" is **56% of a full block's entire
apply CPU**, and "100 ms" is **2.8 full blocks** of CPU crammed into one slot.
Those are not headroom numbers; they are "the block does nothing else" numbers.

### 0.2 Cost of the thing we are trying to replace

I compiled the same arithmetic as `QuantizedLayer::forward`
(`zkml.rs:1132-1147`: `sum = saturating_add(sum, saturating_mul(in, w))`, then
`max(0,sum)`) as a C kernel at `-O2`, for the largest legal model
(8 layers × 45×44 = 16,192 params, 15,840 MACs), 20,000 reps:

```
per-inference: 12.11–12.23 us   (0.765–0.772 ns/MAC)
```

Rust with bounds checks, `Vec` allocation per layer and `i64` saturation will be
slower; **ESTIMATE 20–40 µs** for the in-tree code (not measured in-tree —
doing so would have required a source edit). Call it **~12–40 µs**.

That is the number every zk verifier has to beat. It will not.

---

## 1. Candidate table

Verify and prove columns are per **one proof of one inference**. Where a
benchmark was published single-threaded (ST), that is the column that matters
for a 1–2 vCPU validator; the multi-threaded (MT) number is given only for
context. "NN fit" = can it express an i8×u16→i32 MAC + ReLU layer cheaply.

| System | Field / commitment | Proof size | Verify | Prove | PQ-safe assumptions? | Maturity / audit | NN fit |
|---|---|---|---|---|---|---|---|
| **Plonky3** (Keccak AIR benchmark) | M31 or KoalaBear; Poseidon2/Keccak Merkle + FRI | **1,861 KiB** measured (1,365 keccak-f) | **15.1 ms ST** / 15.8 MT | 3,920 ms ST / 265 ms MT | **Yes** (hash + FRI; no groups) | Production use; audited by Least Authority (final 2024-07-18, upd. 2024-11-07) | Good; M31 covers the i32 accumulator magnitude (sign via field encoding), needs range-check lookups |
| **Stwo** (Blake2s benchmark) | M31/CM31/QM31; Blake2s/Blake3/Poseidon2/Keccak + circle-FRI | **92.5 KiB** measured (2,048 blake2s compressions) | **2.6 ms ST** / 2.5 MT | 1,676 ms ST / 442 ms MT | **Yes** (hash + circle-FRI) | "Production" (SHARP/Starknet); **no external audit linked** in README (2026-11) | Best fit: M31 matches the i32 accumulator magnitude, `no_std` verifier |
| **Plonky2** | Goldilocks (64-bit); Poseidon + FRI | **45 kB** size-optimised; ~100 kB fast mode | ESTIMATE 3–10 ms (**UNVERIFIED** — no first-party number found) | 170 ms recursive proof on a MacBook Pro | **Yes** (hash + FRI) | Mature, widely used; superseded by Plonky3 | Good; 64-bit field costs more per gate than M31 |
| **Halo2 + IPA** | Pasta curves; Pedersen IPA | **< 200 B** | **7–10 ms** (Zcash, single thread) | MNIST (8.1k params / 444.9k FLOPs): **2.36 s** on 32 vCPU | **No** — discrete log (Shor) | Very mature (Zcash); EZKL is Halo2-based | Yes — EZKL exists; but IPA verify grows with circuit |
| **Halo2 + KZG** (EZKL) | BN254; KZG | 6,560 B (MNIST) | **6.69 ms** at MNIST size | 2.45 s on 32 vCPU | **No** — pairings + trusted setup | Mature | Yes (EZKL) |
| **Groth16** | BN254 / BLS12-381 pairings | **128–192 B** | **0.86 ms** native BN254 | seconds–minutes; **new ceremony per circuit** | **No, and cannot be made so** (pairings ⇒ DL) | Very mature | Circuit per model ⇒ per-model trusted setup — disqualifying for a permissionless registry |
| **Spartan** | Curve25519 (R1CS) | ~**10 kB** class at 2²⁰ constraints (O(√\|C\|)) | ~√\|C\| group ops, few ms at 2¹⁷ | fast prover | **No** — discrete log | Research-grade (`libspartan`); no audit found | Yes, but uncompetitive and classical |
| **WHIR** | KoalaBear / M31; hash Merkle | **63 KiB** at 2²², 100-bit | **0.36 ms** | 1.2 s (commit+open) | **Yes** — "secure in the quantum random oracle model" | 2024/25 research impl.; **no audit found** | Yes; best verifier in the table |
| **Binius64** | binary tower field; hash | **304 KiB** (1,365 keccak) | **154.7 ms ST** / 29.2 MT | 499 ms ST / 142 ms MT | **Yes** (hash-based) | 2025 code, MIT/Apache; **no audit found** | Excellent for 64-bit int ops; verifier too slow for 1 vCPU today |
| **Hash-only (today)** | SHA-256/BLAKE3 Merkle + re-execution | 192 B–65 KiB (`ATTEST_PROOF_BYTES`=192) | **0.012–0.04 ms** (measured above) | = run the model | **Yes** | In production here | Exact |

Notes on the two "disqualified" families:

* **Groth16 needs a trusted setup per circuit.** The chain's model registry is
  permissionless and append-only (`zkml.rs:1610-1665`). Every new model would
  need its own ceremony whose toxic waste the chain must trust. That is not a
  cost problem, it is a governance problem, and it is fatal on its own.
* **Halo2/Pasta, Halo2/KZG, Groth16, Spartan all put a discrete-log assumption
  into consensus.** The chain's direction is the opposite: Ed25519 and X25519
  are refused at every height (`post_quantum.rs:152-197`; `docs/CLASSICAL_EXCISION_STATUS.md`).
  Honest caveat: the tree is *not* PQ-pure today — Ristretto Pedersen/stealth
  and MEV sealing are still present and gated (`docs/CLASSICAL_INVENTORY.md:17,44,82`,
  `mev_v4.rs:1-20`). But those are flagged holes scheduled for removal; adding a
  *new* pairing dependency to consensus would move against the declared policy.

---

## 2. Constraint math for our block

### 2.1 What has to be proved

Largest legal model, two shapes, both at the 16,384-param cap:

| Shape | Params | MACs (FLOPs×2) | Neurons | `out·(in+2)` (repo cost model, `zkml_attestation.rs:255-264`) |
|---|---|---|---|---|
| 1 layer 127→128 | 16,384 | 16,256 | 128 | 16,512 |
| 8 layers 45→44 | 16,192 | 15,840 | 352 | 16,544 |

Circuit cost per MAC in a field AIR: 1 mul gate + 1 accumulate + 1 range-check
lookup (product ≤ 2²³). ReLU adds a comparison per neuron (bit-decompose or a
16-bit lookup pair). **ESTIMATE 1.2–2 rows per MAC**, i.e. **~19k–32k rows**,
which pads to **2¹⁵ rows**. For scale: Stwo's own quick benchmark proves
2¹⁸ Poseidon2 permutations. Our circuit is *small* — a toy for any of these
systems, which is exactly why per-proof verify cost is dominated by fixed
overhead, not by our model.

### 2.2 Cost per proof vs the thing it replaces

| System | Verify (1 vCPU basis) | × re-execution (12 µs) |
|---|---|---|
| Re-execution (today) | 0.012 ms | 1× |
| WHIR | 0.36 ms | **30×** |
| Groth16 (PQ ✗) | 0.86 ms | 72× |
| Stwo | 2.6 ms | **217×** |
| Plonky2 (est.) | ~5 ms | ~400× |
| Halo2/KZG (PQ ✗) | 6.7 ms | 560× |
| Halo2/IPA (PQ ✗) | 7–10 ms | 600–830× |
| Plonky3 | 15.1 ms | **1,258×** |
| Binius64 | 154.7 ms | 12,900× |

**Break-even model size.** Re-execution costs 0.77 ns/param (measured). A
verifier of cost `V` ms only pays off above

```
P* = V_ms / 0.00077 ms/param
```

| Verifier | `P*` (params) | vs the 16,384 cap |
|---|---|---|
| WHIR 0.36 ms | 467,000 | 28× |
| Stwo 2.6 ms | 3,380,000 | 206× |
| Plonky3 15.1 ms | 19,600,000 | 1,197× |

That is the whole verdict in one table: **succinctness starts paying at 0.5M–20M
parameters; the chain's own cap is 16k.** Inside this cap, a proof is strictly
more expensive than just running the model, by one to three orders of magnitude.

### 2.3 How many proofs fit in 20 ms / 100 ms

`proofs = budget / verify`. With the ST (1-core) verifier numbers:

| System | 20 ms | 100 ms | Wire-bound (24 MiB / proof) |
|---|---|---|---|
| WHIR (63 KiB) | **55** | **277** | 390 |
| Groth16 (128 B, PQ ✗) | 23 | 116 | — |
| Stwo (92.5 KiB) | **7** | **38** | 265 |
| Plonky2 (45 kB, est.) | 4 | 20 | 546 |
| Halo2/KZG (PQ ✗) | 3 | 15 | — |
| Halo2/IPA (PQ ✗) | 2 | 10 | — |
| Plonky3 (1.86 MB) | **1** | **6** | **12** |
| Binius64 (304 KiB) | 0 | 0 | 81 |

At 2 blocks/s (0.5 s slot), Stwo @20 ms = 14 proven inferences/s; WHIR @20 ms =
110/s. Each carries the full legal model (8 layers, 352 neurons, 16,192 weights).

**But the chain's own anti-DoS cap says something else.** `MAX_BLOCK_PROOF_UNITS
= 2048` exists because verifies serialize on the apply worker
(`mempool.rs:780-786`). At the current 12 µs re-exec that is 24.6 ms worst case.
Swap in a 0.36 ms WHIR verifier and the same cap becomes **737 ms of
single-threaded stall**; a 2.6 ms Stwo verifier becomes **5.3 s**. So adopting
any SNARK forces the cap down to 55 (WHIR) or 7 (Stwo) per block — i.e. the
proof system *reduces* how many ML attestations a block can carry by 30–300×.

The same wall shows up in gas. At 14.3M gas per ms of block CPU, **one** Stwo
verify consumes 37M of the 500M block gas and **one** Plonky3 verify consumes
215M — before any transaction is executed. The block gas cap and the proof-unit
cap would both have to be rewritten around the verifier, which is a consensus
change (`AGENTS.md §7`), not a library swap.

### 2.4 Bandwidth, which nobody prices

24 MiB in a 0.5 s slot is 48 MiB/s = 400 Mbit/s sustained per gossip peer. No
1–2 vCPU home validator has that. Assume a practical **1–2 MiB/block**
(**ESTIMATE**, reasoned from home uplinks; no repo measurement):

| Proof size | Proofs/block at 1 MiB | at 2 MiB |
|---|---|---|
| 63 KiB (WHIR) | 16 | 32 |
| 92.5 KiB (Stwo) | 11 | 22 |
| 304 KiB (Binius) | 3 | 6 |
| 1.86 MB (Plonky3) | **0** | **1** |

Plus two hidden linear costs that already exist in the profile: the proof bytes
are hashed into the tx signing message (BLAKE3, ~1–3 GB/s ⇒ ~0.6–1.8 ms per
1.8 MB proof *per validator*), and block commitment assembly scales at
~0.54 µs/KB (`PERF_PROFILE.md:46`, 387 KB → 0.211 ms) ⇒ +1.0 ms for 1.86 MB.

---

## 3. Where the proof goes

| Placement | Bytes on wire | CPU per block | Chain changes | Verdict |
|---|---|---|---|---|
| **Per tx** (proof in `SysCallVerifyZkMl*` payload) | 63 KiB–1.86 MB **per tx** | `n × V` | none — fits the existing opcode shape | Only sane for ≤100 KiB proofs. At 1.86 MB one tx is 7.8% of the 24 MiB cap and ~30 Mbit/s of gossip. Gas is nearly free (`GAS_ZKML_PROOF_PER_BYTE=2` ⇒ 100 KiB = 200k gas = 0.04% of a block), so **gas does not price the real cost** — the wire and the apply worker do. |
| **Per block** (one aggregate proof in the body/header) | 63 KiB–1.86 MB **per block** | `V` once | new block field ⇒ **frozen-core change** (`AGENTS.md §7`): spec + audit + wire-format bump | Best CPU/bytes, but couples block production to a prover that must finish inside the slot (prove 0.1–2 s, §4) and needs recursion/aggregation. Not justified when a single proof already covers the whole legal model. |
| **Off-chain + on-chain digest** | 32 B (+ optional 192 B attestation) | ~0 | none (use the existing attestation digest) | Cheapest by 4 orders of magnitude. Two flavours: (a) *optimistic*: digest committed, bonded challenge window K blocks, re-execute only on dispute — sound assuming ≥1 honest challenger, PQ-safe, scales to any model size; (b) *trusted verifier*: a relayer/committee/TEE checks the proof and posts the digest — not trustless, say so. |

Cost of one 100 KiB proof carried per tx, priced at the chain's own exchange
rate (14.3M gas/ms of block CPU): 100 KiB of hashing ≈ 0.05–0.1 ms ≈ **0.7–1.4M
gas** of *real* cost against 200k gas charged. The gas table under-prices proof
bytes by ~5×, exactly the failure mode `MAX_BLOCK_PROOF_UNITS` was invented to
paper over.

---

## 4. A concrete minimal design (and what it would NOT hide)

If the chain ever does this, the smallest honest version is:

**Statement.** "I know `x` and an opening of `model_root` such that
`y = Q(M, x)`", where `Q` is the integer forward pass already specified in
`zkml_attestation.rs` (i8 weights, u16 inputs, i32 accumulators, ReLU), and
`model_root` is a Poseidon2 Merkle root over the weights committed in
`ModelSpec` at registration.

**System.** Stwo (M31 circle-STARK, `no_std` verifier) or Plonky3 (audited).
Both are hash-only, so no new classical assumption enters consensus. Public
inputs: `model_root`, `x_commit` (or `x` itself), `y`, domain tag. Proof
~60–100 KiB, verify ~0.4–3 ms, prove **ESTIMATE 0.1–1 s on one core** for the
2¹⁵-row circuit (scaled from EZKL's 2.45 s for a 445k-FLOP model on 32
vCPU; not measured for this circuit).

**Verifier.** One opcode, `SysCallVerifyInferenceProof`, ~40 lines: check
`model_root` is registered, check `x`/`y` shape against the spec, call
`stwo::verify`. Deterministic integer field arithmetic, no floats, no setup.

Gas, at the chain's own exchange rate (14.3M gas per ms of block CPU,
§0.1), is where the current schedule breaks: `GAS_ZKML_VERIFY_IN = 5,000`
buys **0.35 µs** of CPU. A max-size re-execution is charged 5,000 + 2·192 +
16,384 = 21,768 gas against a real cost of ~170k gas (12 µs), i.e. already
under-priced ~8×. Priced honestly, one WHIR verify ≈ **5.1M gas**, one Stwo
verify ≈ **37M gas** (7.4% of `MAX_BLOCK_GAS`), one Plonky3 verify ≈ **215M
gas** (43% of a block). That is not a fee-curve argument; it is the same
"cheap gas, costly verify" hole the proof-unit cap was added to plug.

**What it hides — be exact:**

| Hides | Does not hide |
|---|---|
| `x`, the model inputs (the actual product value: an agent's features/signal) | `y`, unless `y` is replaced by a commitment and revealed later |
| the weights, if `model_root` is all that is published | that *this* `model_root` was used, how many layers (≈ from proof size), and the timing |

One more thing it does not hide, and this is the part marketing always drops:
**that the model is any good.** "The model ran" ≠ "the model is correct or
valuable". A proof of a scam model is a proof of a scam, and the chain already
says this honestly in `zkml_attestation.rs:44-52` ("the claim this supports is
precisely: these outputs are what THIS model produces on THESE inputs").

And the case that kills most of the motivation: **if `x` is public and the model
is public, the proof hides nothing at all and buys nothing at all** — the
verifier already re-executes in 12 µs and gets the same guarantee. The only
statement worth paying 30–1,200× for is *hidden input* (or hidden output)
inference.

Two honest variants, in increasing cost:

1. **Commit-only (recommended if privacy is the goal):** user posts
   `H(y, x_nonce, model_root)`; verification is off-chain by whoever needs it,
   on-chain only if disputed. 32 B, 0 CPU, PQ-safe. Does not prove anything to
   the chain at commit time — say that in the UX.
2. **Optimistic (recommended if bigger models are the goal):** digest + K-block
   challenge window + bonded challenger who re-executes. 32 B, ~0 CPU steady
   state, no size cap, latency K blocks.
3. **On-chain STARK:** the design above. Real, PQ-safe, ~100 KiB and ~3 ms per
   inference, 6–9 engineer-months + audit **ESTIMATE**, for a capability the
   chain cannot currently monetise at 16k params.

---

## 5. Verdict

**Not now. Keep re-execution.** Ranking by value per unit of cost, not novelty:

| # | Option | Cost | What it buys | Verdict |
|---|---|---|---|---|
| 1 | **Keep re-execution** | already paid | sound, PQ-safe, 12–40 µs, no setup, no new assumption | **Do this.** It is not a stopgap; inside a 16k-param cap it is the *correct* engineering answer. |
| 2 | **Fix the claim surface, not the crypto** | days | the honesty gap is already closed (`zkml_capabilities`, `stell_zkmlCapabilities`); next: make `MAX_BLOCK_PROOF_UNITS` and the gas arm quote the measured per-param cost | Cheap, real. |
| 3 | **Optimistic attestation for larger models** | weeks | removes the 16k cap without consensus CPU cost; 32 B, K-block latency | Best value if model size is the actual product need. |
| 4 | **Off-chain proof + on-chain digest** (WHIR/Stwo) | weeks | input privacy for the counterparty, not for consensus | Good if privacy sells; do not put the verifier in the block path. |
| 5 | **On-chain STARK verify** (Stwo, then Plonky3) | months + audit | consensus-enforced input privacy | Only after a product demands it; then Stwo, never Groth16. |
| 6 | **Groth16 / Halo2 / Spartan** | months | small proofs | **Rejected**: Groth16 needs a per-model ceremony and pairings; all three add a discrete-log assumption to consensus, opposite to the declared excision direction. |
| 7 | **Binius64** | months | 64-bit int ops, binary fields | Rejected *today* only on verifier speed (155 ms ST); revisit if their verifier improves. |

Why the answer is "not now", in one line of arithmetic:

> Re-executing the largest legal model costs **12 µs**. The cheapest real proof
> system verifies it in **360 µs**; the systems people actually ship verify it in
> **2.6–15 ms**. Succinctness only breaks even at **~0.5M–20M parameters**, and
> the chain caps models at **16,384**. A proof here is 30–1,200× more expensive
> than the computation it replaces, and it forces
> `MAX_BLOCK_PROOF_UNITS` down from 2,048 to 7–55 per block.

The one thing worth building is **privacy of the inputs**, and that is a
different product from "zkML" — it is a commitment scheme plus, at most, one
verifier call per privacy-bearing transaction, not a per-block proving pipeline.

### What would change this verdict

| Trigger | Then |
|---|---|
| `MAX_ZKML_MODEL_PARAMS` raised past ~500k (a real transformer/CNN) | WHIR/Stwo verify becomes cheaper than re-execution → option 5 |
| A regulator/counterparty requires *consensus-enforced* input hiding | option 5, Stwo M31, budget 100 KiB + 3 ms per tx |
| A WHIR/Stwo verifier measured at ≤100 µs on a 1-vCPU host, audited | option 5 becomes cheap enough to run per tx without touching the proof-unit cap |
| Model registry becomes curated (not permissionless) | Groth16's per-model ceremony stops being fatal — but the PQ objection remains |

---

## 6. Sources

Repo (read, not modified):
`stellereum/src/zkml.rs`, `stellereum/src/zkml_attestation.rs`,
`stellereum/src/svm.rs`, `stellereum/src/runtime/mod.rs`,
`stellereum/src/mempool.rs`, `stellereum/src/post_quantum.rs`,
`docs/PERF_PROFILE.md`, `docs/BFT_COMPARISON.md`,
`docs/CLASSICAL_INVENTORY.md`, `docs/CLASSICAL_EXCISION_STATUS.md`.
Local micro-benchmark: saturated i64 MAC kernel, `gcc -O2`, 20,000 reps
(source in `/tmp/opencode/reexec_bench.c`; not in the repo).

External:
1. Plonky3 — <https://github.com/Plonky3/Plonky3>; audit by Least Authority,
   final 2024-07-18, updated 2024-11-07 —
   <https://leastauthority.com/blog/audit-of-plonky3/>
2. Stwo — <https://github.com/starkware-libs/stwo> (status, `no_std` verifier,
   "external audit reports will be linked here as they are published");
   repo migration to `starkware-libs/proving` end of July 2026.
3. Cross-prover benchmarks, same machine, same task (Plonky3 / Stwo / Binius64) —
   <https://www.binius.xyz/benchmarks/>
4. Binius64 — <https://github.com/binius-zk/binius64>
5. WHIR numbers (2²² poly, 100-bit: 1.2 s, 63 KiB, 360 µs verify; QROM
   security) — <https://hackmd.io/@tcoratger/SJivp8CTJe>; paper record:
   <https://cris.biu.ac.il/en/publications/whir-reed-solomon-proximity-testing-with-super-fast-verification/>
6. Plonky2 (45 kB proofs, 170 ms recursion on a MacBook Pro, ~1M gas) —
   <https://polygon.technology/blog/introducing-plonky2>
7. Halo2 (<200 B proofs, 7–10 ms verify, ~30 ms/tx single-thread in `zcashd`) —
   <https://zodl.com/technical-explainer-halo-on-zcash/>
8. ZKML (EuroSys 2024), end-to-end NN costs — MNIST 8.1k params / 444.9k FLOPs:
   KZG 2.45 s prove, 6.69 ms verify, 6,560 B; IPA 2.36 s, 22.26 ms, 7,680 B
   (r6i.8xlarge, 32 vCPU) — <https://ddkang.github.io/papers/2024/zkml-eurosys.pdf>
9. Spartan — <https://eprint.iacr.org/2019/550>; verifier/proof ~√|C| —
   <https://crypto.stanford.edu/~saba/slides/Quals.pdf>
10. Starknet zkVM/prover benchmark report (Stwo 96-bit, verifier/proof-size
    tables) — <https://docs.starknet.io/learn/S-two-book/benchmarks>
11. Groth16/Bn254 native verification 0.86 ms — arXiv 2609.38223 (secondary
    measurement; **cross-checked only for order of magnitude**).
12. Groth16 128–192 B, three pairings — <https://docs.zkverify.io/architecture/verification_pallets/groth16>
