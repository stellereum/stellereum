# PQ VRF Frontier V2 — Second Deeper Pass (HDAE research, no implementation)

Status: READ-ONLY assessment. No code written, no existing file modified.
Scope: one new file (`docs/PQ_VRF_FRONTIER_V2.md`).
Honest-numbers rule (AGENTS.md §5): every number carries a source
(paper §/table/URL); anything else is marked UNVERIFIED.
Eprint PDFs were largely Cloudflare-blocked for direct fetch; sizes below are
corroborated across ≥2 secondary sources where stated, else UNVERIFIED.

Prior dossier: `docs/PQ_VRF_LAV_FEASIBILITY.md` (LaV: pk ≈ 5.81 KB,
proof σ ≈ 10.27 KB, timings unpublished, unaudited, REJECTED for consensus).
Lead's criterion (the Falcon-analog): LIGHT proofs, FAST, no compromises,
advanced — not brute force. This file checks every assigned candidate against it.

Headline context (May 2026): NIST IR 8610 advanced NINE additional-signature
candidates to Round 3 — FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA,
SQIsign, UOV — while **CROSS was ELIMINATED** (source: NIST IR 8610,
https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf; press release
https://www.nist.gov/news-events/news/2026/05/nine-candidates-advance-third-round-additional-digital-signatures-pqc).
CROSS elimination alone closes candidate #2 below; numbers recorded anyway.

---

## Card 1 — MAYO (multivariate/UOV-based, NIST Round 2 → Round 3)

- pk/sig bytes (Round 2 spec Table 2.1, source:
  https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/mayo-spec-round2-web.pdf
  corroborated by https://openquantumsafe.org/liboqs/algorithms/sig/mayo.html):
  MAYO-1 (L1) pk 1420 B / sig 454 B; MAYO-2 (L1) pk 4912 B / sig 186 B;
  MAYO-3 (L3) pk 2986 B / sig 681 B; MAYO-5 (L5) pk 5554 B / sig 964 B.
  NOTE version skew: pqmayo.org Round-3 proposal re-tunes to MAYO_two
  pk 2928 B / sig 239 B (source: https://pqmayo.org/params-times/). Use Round-2
  figures as canonical; Round-3 deltas marked UNVERIFIED until spec freeze
  (tweak deadline 2026-08-14 per IR 8610).
- Sign/verify timings (source: MAYO Round-2 spec §3.3.1, Table 3.3, Ice Lake
  Xeon Gold 6338 @2.0 GHz, AVX2+AES-NI, median of 1000 runs):
  MAYO-2 KeyGen ≈ 48 µs, Sign(+ExpandSK) ≈ 143 µs, Verify(+ExpandPK) ≈ 28 µs.
  GFNI/AVX-512 build (source: https://pqmayo.org/params-times/):
  MAYO_two KeyGen 26.9 µs / Sign 50.6 µs / Verify 20.9 µs. FAST — passes speed.
- Determinism (can it serve as VRF-via-deterministic-sign?): MAYO signing
  derives `salt ← SHAKE256(M_digest ‖ R ‖ seed)` where R is zeros
  (deterministic mode) or random (spec Alg. 2 as reproduced in the 2025 fault-attack
  paper https://eprint.iacr.org/2025/2101.pdf §5.1). So a deterministic mode
  EXISTS — but it does NOT help: UOV-family signatures are inherently
  NON-UNIQUE (many vinegar assignments / SampleSolution outputs satisfy one
  message; signing restarts on failure with ctr 0..255). Deterministic salt
  reproduces *one* valid signature, but other valid signatures for the same
  message exist and verify — anyone holding sk (or a faulted variant) can
  grind outputs. VRF uniqueness FAILS. Deterministic mode additionally widens
  the fault-attack surface (single-fault full key recovery demonstrated against
  deterministic MAYO, 2025/2101). VERDICT: not VRF-usable.
- Maturity/audit: NIST Round 2 → Round 3 (May 2026). Wedge/exterior-product
  attack cost MAYO-2 ≈ 30 bits of security (source: IR 8610 §3.12); parameters
  must be re-tuned. No audit found (UNVERIFIED absence claim). Apache-2.0
  reference impl (PQCMayo/MAYO-C).
- Assumption: Oil-and-Vinegar / MQ-system hardness over F16 (multivariate).
  New-family risk comparable to the ML-DSA-rejection rationale; decision
  belongs to lead.

## Card 2 — CROSS (code-based, NIST Round 2, ELIMINATED)

- pk/sig bytes (source: CROSS Round-2 spec Table 4,
  https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/spec-files/cross-spec-round2-web.pdf):
  smallest proofs at L1: RSDP(G)-1-small pk 54 B / sig 8960 B (~8.75 KB);
  RSDP-1-small pk 77 B / sig 12432 B (~12.1 KB). Fast corners larger
  (RSDP-1-fast 18432 B); L5 up to ~74 KB (RSDP-5-fast 74590 B).
- Timings (source: CROSS Round-2 slides, i7-12700K @3.6 GHz, avg 10k runs):
  L1 RSDP(G)-fast Sign 0.744 Mcycles (≈ 0.21 ms derived) /
  Verify 0.482 Mcycles (≈ 0.13 ms derived); keygen negligible.
  FPGA Artix-7: sign 0.34–4.6 ms (source: https://eprint.iacr.org/2025/1161.pdf).
  FAST — but proofs are the problem.
- Determinism: Fiat-Shamir over t parallel 5-pass rounds with per-round seed
  trees; signing randomized by construction. No deterministic mode advertised.
  Transcripts non-unique by design (challenge responses admit many valid
  openings). VERDICT: not VRF-usable; and smallest proof (~9 KB) already
  exceeds LaV (10.3 KB) only marginally while pk advantage (54 B) is irrelevant
  to per-block proof budget.
- Maturity/audit: ELIMINATED from Round 3 (source: IR 8610 §3 — "security
  uncertainty + less competitive performance"; underlying RSD problem younger
  than SPHINCS+ hashes). Round-2 history: parameter-changing attack
  (https://eprint.iacr.org/2025/127, per IR 8610) and an HVZK-proof flaw note
  (https://eprint.iacr.org/2025/359, via official comments). No audit found.
- Assumption: Restricted Syndrome Decoding (young code assumption).
- VERDICT: dead for the Falcon-analog on proof size alone; NIST elimination
  confirms. CLOSE.

## Card 3 — LMS/XMSS/HSS (NIST SP 800-208, STATEFUL hash-based)

- Sig bytes (source: Romansky–Mazzuchi–Sarkani libOQS benchmark data v0.11.1-dev,
  https://doi.org/10.48550/arxiv.2502.06033, Tables 2–3):
  LMS_SHA256_H5_W8 1.27 KB / pk 60 B; LMS_SHA256_H20_W8 1.73 KB;
  HSS H20_W8+H20_W8 (2^40 sigs) 3.52 KB; XMSS-SHA2_10_256 2.44 KB / pk 68 B;
  XMSSMT-60/12 up to 27 KB. So the "2–3 KB" brief estimate is CONFIRMED for
  practical single-tree/HSS configs.
- Timings: LMS verify 0.35–6.8 Mcycles (≈ 0.1–2 ms class, x86); XMSS verify
  ~2–5 Mcycles (same source). Keygen/signing costs scale with Winternitz
  chains (W=8 slowest to verify). FAST ENOUGH.
- Determinism: NO — LM-OTS signing samples a fresh randomizer C per signature
  (per RFC 8554; § pointer UNVERIFIED). Uniqueness holds only in the
  once-per-leaf sense: each OTS key is used at most once, so per-index outputs
  are single — but signing the same message at two indices yields two valid
  signatures. As a VRF this is an *indexed* (stateful) VRF at best, requiring
  protocol-semantics change (cf. prior dossier §6 hash-iVRF note).
- Statefulness catch — ASSESSED HONESTLY, near-fatal for validator keys:
  SP 800-208 §1.2 + §8.1 REQUIRE hardware modules that never export secret
  material, precisely because OTS reuse after restore/fork/backup is a
  forgery-grade break (two sigs under one OTS key → arbitrary forgery).
  Validator hot keys live the opposite life: failover replicas, snapshot
  restores, slashing-protection DBs that already struggle with exactly this
  class of bug (double-sign). A crashed-and-restored validator reusing a leaf
  does not just equivocate — it degrades to forgeable keys. HSS trees to 2^40
  cover a career of slots but do not fix crash-reuse. Mitigation (HSM-enforced
  monotonic counters, no-export keys) contradicts our operational model and
  adds hardware dependency per validator. VERDICT: lightest STANDARDIZED
  option (1.3–3.5 KB) with hash-only assumptions, but statefulness is
  FATAL-or-near for consensus validator keys as operated here; recommend
  against, absent a hardware-state decision owned by lead.
- Maturity/audit: HIGHEST of all cards — NIST SP 800-208 (2020), RFCs
  8391/8554/9858, libOQS + Romansky benchmark corpus. Assumption: hash
  preimage/second-preimage only (most conservative in the field).

## Card 4 — Newest compact lattice VRFs, 2024–2026 (beyond LaV)

Triage method: title/abstract review of eprint 2024–2026 "lattice VRF" hits
(full text largely Cloudflare-blocked; § pointers UNVERIFIED unless noted).

- 2026/772 (Xu–Esgin–Steinfeld, ACISP'26, https://eprint.iacr.org/2026/772):
  a ring-VRF compiler instantiated ON LaV + LB-VRF, explicitly calling both
  "state-of-the-art lattice VRFs." CONFIRMS no newer smaller lattice VRF has
  displaced them; ring layer only ADDS proof overhead. No sub-5 KB candidate here.
- 2024/643 (Malavolta: key-homomorphic + aggregate VRFs; LWE standard-model
  construction claimed): abstract-level only; NO concrete byte/timing table
  retrieved → sizes UNVERIFIED, presumed large (standard-model lattice VRFs
  historically MB-scale). Not a candidate; flagged for cryptographer follow-up only.
- Unbiasable-VRF line — Brandt https://eprint.iacr.org/2025/766 + Giunta–Stewart
  VUF-then-Hash: Brandt gives a GENERIC transform (standard-model, plausibly PQ,
  preserves aggregatability/key-homomorphism, fixes a folklore VUF-then-Hash
  weakness) with NO concrete instantiation sizes — generic-only, NOT
  implementable as specified. Giunta–Stewart is definitional. VERDICT:
  important future security property (unbiasability) with zero deployable bytes today.
- Net: NOTHING in 2024–2026 beats LB-VRF (~5 KB, few-time) or LaV (~10.3 KB,
  long-term) on lattice-VRF proof size at comparable maturity. The lattice-VRF
  frontier is FLAT since Crypto'23. (Bonus non-lattice find recorded in Card 7.)

## Card 5 — Threshold-VRF path (FROST-style distributed randomness, PQ)

- Classical FROST/ROAST (Schnorr/ECDSA) is discrete-log — NOT PQ. Question is
  whether a PQ threshold *signature* yields a distributed VRF.
- Lattice threshold signatures (all signatures, not VRFs):
  TRaccoon (https://eprint.iacr.org/2024/184): 13 KiB sig + 40 KiB comm/user,
  N,T ≤ 1024, MLWE/MSIS-family; Espitau et al. (https://eprint.iacr.org/2024/496):
  2-round, ~11 KB at T = 1024 (new AOM-MLWE assumption); PKC'25 compact
  (Dilithium-style, T ≤ 8): ~2.7 KB vs 2.42 KB plain Dilithium (UNVERIFIED —
  abstract-level). No "threshold Falcon" with compact standard-assumption
  parameters found in triage (UNVERIFIED absence).
- CATEGORICAL gap: a threshold signature certifies a message — it does not
  GENERATE verifiable randomness with uniqueness. Threshold signing uses
  rejection sampling / randomized nonces, so joint outputs are non-unique and
  grinding-prone; VRF pseudorandomness + uniqueness proofs do not transfer.
  A true distributed VRF needs threshold PRF evaluation (e.g. DVRFwCP-style,
  https://eprint.iacr.org/2024/1130 claims constant-size proofs without in-
  verification pairings — assumption/mechanism details UNVERIFIED, classical-
  pairing-adjacent until confirmed). VERDICT: threshold path is COMPLEMENTARY
  (committee can co-sign a beacon) but NOT a substitute — it still needs an
  underlying randomness source, which is the unsolved piece. Fit for beacons:
  co-signing YES, generation NO.

## Card 6 — ZK-STARK of correct PRF evaluation (prove AES/SHAKE-PRF under committed key)

Included to kill-or-rescue with numbers. VERDICT: KILLED.

- Proof bytes: RISC Zero hash-chain benches (source:
  https://github.com/risc-zero/zk-benchmarking): 183–205 KB for 10–100 hashes;
  Miden VM 87–105 KB. Independent zkVM SHA-256 benches (source: Starknet
  benchmarks, Jul 2025) put succinct proofs at 223 KB (R0) – 1.3 MB (SP1) for
  byte-scale SHA-256 workloads. A single PRF evaluation proof is therefore
  ~50–200+ KB — 5–20× LaV, the thing we are trying to beat.
- Prover time: RISC Zero 1.3–7.3 s (Dell XPS class) for short hash chains;
  zkVM SHA2-256B benches run 7–45 s CPU-only (same sources). Per-slot
  validator proving at seconds-scale is operationally absurd for sortition.
- Verify is fine (~2–25 ms) but irrelevant given proof size + prover cost.
- Escape hatch that fails: Groth16-wrapped zkVM receipts are 256 B (R0) /
  530 B (SP1) (source: Velička thesis benchmarks, https://dspace.cuni.cz
  …/130423510.pdf) — but Groth16 is pairing-based (NOT PQ) and adds ~1.5–9 min
  proving. Wrapping a STARK in a non-PQ SNARK forfeits the entire project.
- A PQ-SNARK-wrapped STARK (e.g. LaBRADOR-based Falcon aggregation per
  https://eprint.iacr.org/2024/311) inherits lattice-proof overhead back
  (~KBs–10s of KB, UNVERIFIED estimate) — circular, no gain demonstrated.
- VERDICT: STARK-of-PRF is heavier, slower, and operationally heavier than
  every card above. KILLED with numbers.

## Card 7 — Bonus frontier find: DeuringVRF (isogeny VUF→VRF, NOT lattice)

Found in triage; recorded because it is the ONLY post-quantum VRF with
Falcon-class compactness. NOT recommended — assumption novelty blocks it —
but lead should know it exists.

- Sizes (source: Leroux 2023/1251 Table 1, https://eprint.iacr.org/2023/1251;
  Eurocrypt'25 ch. 7, https://doi.org/10.1007/978-3-031-91098-2_7):
  pk 192 B / proof 256 B (≈ 448 B combined; VRF output adds 4λ ≈ 32 B).
  Two orders of magnitude below LaV.
- Timings (non-optimized C impl, same sources): keygen ~111–127 ms,
  eval ~160–175 ms, verify ~17–20 ms. Verify is missile-fast; eval is slowish
  but off the per-verifier hot path (each validator evaluates once, all verify).
- Uniqueness: UNCONDITIONAL (only PQ-VRF with this property per author;
  lattice VRFs give computational uniqueness at best). Deterministic evaluation:
  YES. Unbiasable VRF transform applies at negligible cost (ROM).
- Assumption: One-More Isogeny Problem (OMIP, NEW) over supersingular curves
  with 2-dim HD representations — post-SIDH-attack machinery reused
  constructively. Security history is SHORT; implementation unaudited;
  isogeny family carries the SIDH-collapse memory. This trips the same
  new-assumption wire that rejected ML-DSA-adjacent additions — only harder.
- VERDICT: meets the LIGHT + FAST + ADVANCED shape on paper better than
  anything else found, but fails maturity/audit and novel-assumption gates.
  Track passively (revisit if OMIP survives 3–5 years + audit); FORBIDDEN for
  consensus wiring now.

---

## Comparison table (sorted by proof/signature bytes; VRF-suitability flagged)

| Candidate | Proof/sig bytes | pk bytes | Timings (eval/sign → verify) | Deterministic? | VRF-unique? | Assumption | Maturity |
|---|---|---|---|---|---|---|---|
| DeuringVRF (isogeny) | ~256 B | 192 B | 160 ms → 18 ms | YES | YES (unconditional) | OMIP (new) | paper + unaudited C impl |
| MAYO-2 (sig, NOT VRF) | 186 B | 4912 B | 143 µs → 28 µs | mode exists, outputs non-unique | NO | UOV/MQ | NIST R3, wedge-tuned, unaudited |
| LMS H5/W8 (sig, stateful) | 1.27 KB | 60 B | ~ms → ~0.1 ms | NO (fresh C/sig) | index-only | hash | SP 800-208 STANDARD |
| XMSS-10_256 (sig, stateful) | 2.44 KB | 68 B | ~ms → ~1 ms | NO (fresh randomness) | index-only | hash | SP 800-208 STANDARD |
| HSS 2^40 (sig, stateful) | 3.52 KB | 60 B | ~ms → ~ms | NO | index-only | hash | SP 800-208 STANDARD |
| LB-VRF (few-time VRF) | 4.94 KB | 3.32 KB | 3.1 ms → 1.3 ms | derived-randomness* | YES (computational) | MSIS+MLWE | paper + incomplete Rust proto |
| CROSS small (sig, NOT VRF) | ~9 KB | 54 B | 0.2 ms → 0.13 ms | NO | NO | RSD (young) | ELIMINATED R3 |
| LaV (long-term VRF) | 10.27 KB | 5.81 KB | UNPUBLISHED | needs crypto review† | YES (computational) | MLWR+MSIS | paper + unaudited C impl |
| Threshold lattice sigs | 2.7–13 KB | KBs | 0.5–7 s (distributed) | NO | NO (not VRFs) | MLWE/MSIS/AOM | papers + protos |
| STARK-of-PRF | 90–200+ KB | n/a | seconds → ~ms | YES | YES (proof) | hash | products, but KILLED |

\* LB-VRF Eval randomness derivation per paper; reuse bound k is the binding
constraint (prior dossier §1). † LaV masking-`y` derivation needs cryptographer
sign-off (prior dossier §2.3).

Top-3 by proof bytes among ACTUAL VRFs (excluding signatures-that-are-not-VRFs):
**DeuringVRF ~256 B → LB-VRF ~5 KB (few-time) → LaV ~10.3 KB.**
If stateful signatures are counted as indexed randomness: LMS 1.27 KB leads,
with the §Card-3 fatality attached.

---

## "Own-scheme" sketch — IF nothing fits (and nothing does)

Candidate combiner: **MAYO-deterministic-sign-then-hash**: validator holds a
MAYO keypair; per slot computes `σ ← MAYO_sign_det(sk, slot)` (R=zeros mode),
publishes `y ← H(σ ‖ slot ‖ pk)`, validators check MAYO-verify then recompute
the hash. Proof bytes would be ~186–454 B — the lightest hash-and-check layer
imaginable.

WHY THIS MUST NOT BE BUILT without external cryptographers (NON-STANDARD —
no security argument exists for any of the following):

1. UNIQUENESS FAILS OPENLY: UOV signatures are non-unique; a second valid
   σ′ for the same slot verifies and hashes to a different y → the "VRF"
   is grindable by the key holder. This is not a tight-corner bug, it is the
   design: multivariate signing samples among many preimages by construction.
2. A uniqueness fix requires proving CORRECT signing inside a NIZK (the
   verifier must bind σ to a canonical evaluation), re-introducing KB-scale
   lattice/MQ proofs — the lightness evaporates exactly where LaV already is.
3. Deterministic mode is the fault-attack bullseye (single-fault key recovery
   per 2025/2101); hedged/randomized mode restores grinding (different σ per
   draw). There is no safe cornertoday — UNVERIFIED either way.
4. Salt/seed-domain separation, restart-ctr (0..255) canonicalization, and
   expanded-key handling each carry soundness-critical choices no in-house
   review can bless.
5. CROSS-substitution does not help (same non-uniqueness + 9 KB+ proofs +
   eliminated standing); LMS-substitution converts the sketch into the
   stateful indexed-VRF of Card 3 with its operational fatality.

PHASE-GATE (binding): spec note → sandbox KATs (no consensus import) →
EXTERNAL cryptographer review + audit → ONLY THEN revisit wiring.
CONSENSUS WIRING FORBIDDEN BEFORE PASSED EXTERNAL AUDIT. Any deviation fails
review under AGENTS.md §7 (frozen core) and the lead's no-unaudited-crypto rule.

---

## Bottom line + recommendation

No assessed candidate meets the Falcon-analog bar (light + fast + advanced +
mature): MAYO/CROSS are fast but non-unique non-VRFs (CROSS also eliminated);
LMS/XMSS are light and standardized but stateful (operationally near-fatal)
and non-deterministic; the 2024–2026 lattice-VRF frontier is flat (LaV/LB-VRF
still SOTA); threshold signatures certify but do not generate randomness;
STARK-of-PRF is killed at 90–200+ KB proofs with seconds-scale provers; the
lone compact standout (DeuringVRF, ~448 B combined) hangs on a brand-new
isogeny assumption with unaudited code.

**RECOMMENDATION: adopt NOTHING for consensus sortition; keep ECVRF until the
PQ cutover forces the choice, cap this line of inquiry at passive tracking of
DeuringVRF assumption maturity + Brandt-style unbiasability requirements, and
approve at most sandbox KAT measurement of reference implementations —
NO wiring, NO new crypto code, NO audit-bypass, per standing gates.**
