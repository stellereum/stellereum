# PQ VRF — LaV Feasibility Dossier (HDAE research, no implementation)

Status: READ-ONLY assessment. No code written, no existing file modified.
Scope: one new file (`docs/PQ_VRF_LAV_FEASIBILITY.md`).
Honest-numbers rule (AGENTS.md §5): every number carries a source
(paper §/table); anything else is marked UNVERIFIED.

## 0. Paper URLs (verified by title match)

- LaV: **https://eprint.iacr.org/2022/141** — Esgin–Steinfeld–Liu–Ruj,
  "Efficient Hybrid Exact/Relaxed Lattice Proofs and Applications to
  Rounding and VRFs", Crypto'23 proceedings pp. 484–517
  (DOI 10.1007/978-3-031-38554-4_16). Current eprint v2 revised
  2023-09-01 (CC BY). NOTE: direct PDF fetch was Cloudflare-blocked for
  curl; all LaV numbers below are cross-corroborated across ≥2 secondary
  sources (peer paper tables + 2026/772). Full-text § citations are to
  the best of the author's knowledge from indexed snippets — treat §
  pointers as UNVERIFIED, sizes as corroborated.
- LB-VRF: **https://eprint.iacr.org/2020/1222** — Esgin et al.,
  "Practical Post-Quantum Few-Time VRF with Applications to Algorand".
  NOTE: eprint metadata says published at **FC'21** (proceedings pp.
  560–578), not FC'19 — the brief's "FC'19" label appears off by two years.
- SOTA confirmation: **https://eprint.iacr.org/2026/772** (Xu–Esgin–
  Steinfeld, *preprint*, Apr 2026) instantiates its ring-VRF compiler on
  exactly "the long-term lattice VRF LaV (Crypto'23) and the few-time
  lattice VRF LB-VRF (FC)" and calls both "state-of-the-art lattice VRFs".

## 1. Construction summary

**LaV (long-term, stateless).** Folklore PRF+NIZK VRF paradigm, lattice
instantiation: secret `s`, public key `t = ⌊A·s⌉_p` (rounded MLWR
sample); VRF value `v = ⌊⟨b,s⟩⌉_p` with `b ← G(m)` (random oracle).
Correctness of rounding is proven by a LANES+-based proof of rounding:
a hybrid exact/relaxed ZK system (relaxed RPoK over the long witness `s`
+ exact LANES proof over only the short rounding error `e`). The exact
error check is what gives **uniqueness = YES** (adversary cannot pass
verification with two different errors — paper App. C). Underlying PRF
is (approximately) **key-homomorphic** (paper Table 1: Key Hom. ✓).
Assumption: **Module-LWR** for pseudorandomness (+ MSIS-type binding for
the commitment/LANES soundness — combined theorem statement UNVERIFIED,
not read in full text). Evaluations per key: **2^128** (practically
unrestricted; source: paper intro). Sizes (current eprint v2 §6.5,
corroborated by 2026/772 §5: `|pk|≈5.81KB, |v|≈124B, |σ|≈10.27KB`):
**pk ≈ 5.81 KB (5810 B), proof σ ≈ 10.27 KB** (= RPoK 3.18 KB + LANES
`|tL|+|πL| ≈ 7.1 KB), VRF value 124 B.** Proceedings version was larger
(pk 6420 B / proof 11980 B / v 124 B — source: 2022/993 ACM Table 1 row
"LaV [18]"); use the **10.27 KB** figure as current. Timings: **NOT
published** — 2022/993 Table 1 shows "-" for LaV keygen/eval/verify.

**LB-VRF (few-time).** Secret short vector `s`, pk `t = A·s`; value
`v = ⟨b,s⟩` with **no error** (exact inner product); Fiat-Shamir-with-
aborts relaxed PoK of `s`. Assumption: **Module-SIS + Module-LWE**
(source: paper abstract). **Uniqueness = YES**, and soundness holds even
past the few-time bound — the `k`-time limit is only for pseudorandomness
(source: paper §1). Sizes/timings: **value 84 B, proof ≈ 5 KB
(4940 B), pk 3320 B; keygen 0.33 ms, eval 3.1 ms, verify 1.3 ms**
(sources: abstract "~5KB / ~3ms / ~1ms"; exact figures 2022/993 Table 1).
Most efficient instantiation is **1-time** (k=1); marginal variants reach
~5 evaluations (source: LaV paper intro). Disqualifying for sortition on
its face: a per-round (or per-few-rounds) key refresh plus ~8.3 KB
effective per-round communication (source: 2022/993 § discussion).

## 2. Implementability verdict: CONDITIONAL (no, not without a cryptographer)

LaV is fully *described* (algorithms LANES/LANES+/rounding/LaV.Eval as
Alg. 4 with numbered steps) but NOT turnkey. Gaps requiring a
cryptographer (not competent-engineers-alone):

1. **Parameter derivation is analysis-bound, not tabulated copy-paste.**
   Challenge space C per Eq. (9), moduli `q, q̂` with `q̂ ≡ 2l+1 (mod 4l)`,
   compression `D=13`, rejection bound `‖ŵ2‖∞ > 2^{K-1} − w_γ·q/p`,
   Bai–Galbraith compression at Eval Step 26 — each constant is justified
   by the new invertibility/rejection analysis; a transcription error
   breaks soundness *silently* (proofs still verify among themselves).
2. **Novel theorem risk.** The generalized challenge-difference
   invertibility bound (γ>1, small d=32) is a new result; instantiating
   `(γ, d, q)` outside its proven envelope voids the soundness proof.
3. **Determinism/uniqueness subtlety.** Eval samples masking `y`
   (Alg. 4 Step 15) with a restart check (Steps 19–20). A VRF needs
   unique-per-(sk,m) outputs; whether `y` is derived deterministically
   via domain-separated PRG on (sk,m) without leaking `s` is exactly the
   class of issue behind the deterministic-Falcon warning — needs
   cryptographer sign-off, MUST NOT be improvised.
4. **Rounding range proof edge cases.** β-ary digit range enforcement on
   the error `e`; off-by-one admits two valid errors → uniqueness break
   → consensus split on sortition. Needs proof-level review.
5. **No KAT vectors in the papers** (UNVERIFIED — none found in indexed
   content). The reference C impl's `test.c` is the only de-facto vector
   source and is itself unaudited.
6. **Side channels.** Fiat-Shamir-with-aborts + Gaussian/uniform sampling
   is timing-sensitive; neither reference impl claims constant-time
   (LB-VRF README explicitly defers it).

## 3. Dependency analysis (verified against tree, read-only)

Need: (a) SHAKE/XOF, (b) module-lattice NTT/polynomial arithmetic over
`R_{q,d}` with small splitting `d=32`, (c) discrete Gaussian + bounded
uniform sampling with exact rejection, (d) LANES+ proof codec
(commitments, compression `D=13`, challenge hashing), (e) constant-time
discipline + zeroization.

| Need | In tree? | Evidence |
|---|---|---|
| SHAKE256 (Rust) | NO | `sha3` absent from `stellereum/Cargo.lock` (only `sha2`, `blake3` present); Falcon's SHAKE lives inside `pqcrypto-falcon`'s C archive, not callable from Rust |
| NTT / module-lattice poly math | NO | no NTT crate in lockfile; `falcon-rust` FFT is Falcon-NTRU-ring-specific (`fast_fft.rs`, `cyclotomic_fourier.rs`), different rings/moduli — not reusable for MLWR `R_{q,d}` |
| Discrete Gaussian sampler | NO (reusable) | `falcon-rust` `samplerz.rs`/`ffsampling.rs` = Falcon trapdoor sampling, wrong distribution/role for FS-abort masking; `rand_distr` in lockfile is transitive-only (via `falcon-rust`, rand 0.10) and not crypto-safe sampling |
| Rejection sampling, LANES+ codec, KAT | NO | nothing lattice-VRF-shaped in `stellereum/src/` (only `post_quantum.rs` Falcon-512, ECVRF-phase-1 notes) |
| zeroize, rand 0.8 | YES | in lockfile; usable hygiene, not math |

Net: ~everything mathematical must be built (or vendored from the
reference C impl with a full review). New-crate surface (e.g. `sha3`) is
small but needs lead approval per frozen-core hygiene.

## 4. Risk register

- **Audit/standardization: NONE.** Peer-reviewed papers (Crypto'23,
  FC'21) ≠ audited code. No audit of either reference implementation
  found (web + GitHub search; absence claim UNVERIFIED but no audit is
  claimed anywhere). Not NIST/standardized; not on any standards track
  found.
- **Implementations (research-quality, unaudited):** LaV — C,
  https://gitlab.com/raykzhao/lav (CSIRO Data61, 81 commits, created Aug
  2023, dirs `lanes/ lanes_plus/ lav/ rounding/ prg/`, ships `cpucycles`
  benchmark + `test.c`; license **BSD Zero Clause** — permissive, no
  copyleft obstacle). LB-VRF — Rust,
  https://github.com/zhenfeizhang/lb-vrf (10 stars, 25 commits; README
  checklist openly incomplete: no NTT, no Montgomery, no HNF secrets,
  no zeroize, no constant-time, no docs, many-time scheme undecided).
- **Side channels:** both impls non-constant-time by admission/omission;
  Gaussian/abort sampling in a validator hot path = timing-leak surface
  on `s`. Any Phase B must add CT as explicit work, not assumption.
- **Assumption novelty (flag for lead):** LaV adds **Module-LWR** —
  less battle-tested than MLWE — plus a brand-new invertibility theorem.
  This is a *new PQ assumption family member* beyond deployed Falcon;
  the ML-DSA rejection rationale (no second PQ assumption) arguably
  applies here too. Decision belongs to lead; recorded, not litigated.
- **Patent/licensing:** no patent mention found in indexed paper content
  (UNVERIFIED — full-text patent search not performed); code licenses
  permissive (0BSD LaV; LB-VRF license file not confirmed — UNVERIFIED).
- **Consensus-safety:** uniqueness bugs don't just leak — they fork
  sortition. Combined with no KAT and no audit, wiring risk is
  unacceptable before external review (see Phase C gate).

## 5. Phased plan (NO code; estimates = judgment, UNVERIFIED)

- **Phase A — Spec transcription + KAT (2–4 eng-weeks + cryptographer
  review).** Transcribe LaV params/algorithms from eprint v2 into a
  version-pinned spec note; extract de-facto KAT from reference `test.c`;
  reconcile 10.27 KB figure; measure reference-C timings on our hardware
  (fills the missing timing row honestly). Deliverable: numbers, not code.
- **Phase B — Sandbox prototype, OUTSIDE consensus (6–12 eng-weeks,
  needs lattice engineer).** Separate crate, never wired to sortition;
  differential-test vs C reference; constant-time sampling pass;
  proof-size/timing benchmarks on validator-class hardware. Explicitly:
  no `stellereum/src/` touch, no feature gate, no activation height.
- **Phase C — External audit, then (and only then) consider wiring
  (audit lead time 8+ weeks, plus remediation).** CONSENSUS WIRING IS
  FORBIDDEN BEFORE EXTERNAL AUDIT. Realistic path to mainnet: 6–12
  months conditional on audit outcome. Total effort order: ~4–6
  person-months + audit budget (UNVERIFIED estimate).

## 6. Bottom line + recommendation

| Option | Proof bytes | Assumption | Maturity | Effort to wire safely |
|---|---|---|---|---|
| ECVRF (retiring) | 80 B proof / 32 B pk / 32 B value (2022/993 Tab.1) | discrete-log (classical — rejected) | standardized, fast (0.1 ms) | n/a |
| LaV (eprint v2) | **~10,270 B** proof / 5810 B pk / 124 B value; unlimited evals | MLWR (+MSIS) — new, less-tested | paper peer-reviewed; code unaudited; timings unpublished | 4–6 person-mo + audit |
| LB-VRF | 4940 B proof / 3320 B pk / 84 B value; **1-time keys** | MSIS+MLWE | paper peer-reviewed; Rust proto incomplete/unaudited | unusable for sortition (key refresh every round) |
| SPHINCS+ (lead: rejected) | ~8 KB (per project brief) | hash (conservative) | NIST standard | rejected as brute-force |
| Hash iVRF (2022/993, same authors) | 608 B proof / 32 B pk; eval 0.01 ms / verify 0.02 ms | hash only | paper; **stateful N=2^18**, needs protocol-semantics change | needs lead decision on indexed-VRF relaxation |

**RECOMMENDATION: Do not adopt LaV for consensus sortition — proofs
(10.3 KB) exceed the already-rejected SPHINCS+ (~8 KB), timings are
unpublished, implementations are unaudited research code, and it adds an
MLWR assumption; approve Phase A (spec transcription + reference-C
timings) at most, and revisit only after measured timings plus a passed
external audit.**
