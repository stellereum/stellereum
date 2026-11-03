# VRF Cryptanalysis — deterministic-Schnorr construction (`src/vrf.rs`)

Scope: the PHASE-1 wiring VRF — a deterministic Schnorr signature used AS a VRF
(`output = BLAKE3(R || pk || seed)`, proof `(R, z)`), NOT RFC 9381 ECVRF.
Read-only analysis; executable games live in
`tests/vrf_cryptanalysis_tests.rs` (extends `tests/vrf_audit_tests.rs` and
`tests/vrf_bls_adversarial_tests.rs` without duplicating them).
Prior battery (assumed proven, not re-litigated): determinism HOLDS, nonce
uniqueness HOLDS, soundness HOLDS (64-position flip sweep), fail-closed edges
HOLD, uniqueness DOES NOT HOLD (holder-minted second proof).

All numbers below are measured from `cargo test --test vrf_cryptanalysis_tests`
(`GRIND:` / `EDGE:` / `MALLEABILITY:` lines, `-- --nocapture`), deterministic
fixtures, no randomness.

## 1. Per-property verdicts

| # | Property | Verdict | Proof sketch / test pointer |
|---|---|---|---|
| 1 | Completeness (honest prove→verify) | HOLDS | `vrf_prove` (`src/vrf.rs:499`) → `vrf_verify` (`:518`) round-trips for 100×8 + 128×32 fixture matrix; `key_substitution…` control re-pins victim minting. |
| 2 | Determinism (same key+input ⇒ same bytes) | HOLDS | Prior audit (100×8). Re-pinned incidentally: `grinding_…` calls `vrf_prove` twice per input (mint + assert round-trip) with byte-equality via `assert_eq!(vrf_verify…Some(output))` on the identical envelope. |
| 3 | Unforgeability / soundness (no secret ⇒ no valid proof) | HOLDS | Prior 64-position sweep. Extended here to the FULL 512 single-bit mutants + 256 output-bit mutants + full-byte flips on a FRESH proof — all `None` (`malleability_fresh_proof…`). Forged/random corpora refused (prior BLS-adversarial file). |
| 4 | Uniqueness (one verifiable output per pk+input) | DOES NOT HOLD | Construction limitation, demonstrated in both the prior audit (alternate-nonce second proof) and here constructively at scale: 128 inputs × 32 holder-ground alternates ALL verify (`grinding_…`). No fail-closed tweak inside Schnorr can close this; only the phase-2 ECVRF swap can. |
| 5 | Key-substitution resistance (adversary claims victim identity) | HOLDS at registry layer; DOES NOT HOLD at raw-proof layer — BY DESIGN | `key_substitution_proof_binds_key_not_identity`: attacker proof VERIFIES under attacker key (`Some`) — raw `vrf_verify` authenticates the KEY, never the identity — but `verify_vrf_seed_for_validator` for the victim id returns `None`, and the forged binding (attacker Falcon sig over `(victim_id‖attacker_pk)`) fails `VrfBinding::verify` + `register`. Trust boundary: identity lives SOLELY in the Falcon-signed binding (`src/vrf.rs:240,267,310`); a proof without a registry-bound key mints nothing. |
| 6 | Pseudorandomness / output uniformity | HOLDS (statistical) | 4096 holder-ground outputs: first-byte χ² = 277.1 on 255 df (uniform mean 255, σ≈22.6 → +1σ); bin min 6 / max 31 at expected 16.0; first-bit fraction 0.4995. Gates: χ² < 500, balance ±0.10 (`grinding_…`). |
| 7 | Self-grinding resistance (holder best-of-N) | DOES NOT HOLD (quantified, §2) | Holder picks min ticket of N: measured = closed form `1-(1-p)^N` within sampling noise. This is the SAME non-uniqueness as #4 viewed as an election attack. |
| 8 | Nonce-misuse resistance (cross-input/nonce reuse, tag confusion) | HOLDS | Nonce binds secret+input (distinct R per input/key, prior audit). `domain_tags_distinct_and_binding`: all six domain tags pairwise distinct; nonce/challenge tag swap → `None`; one-bit proof-domain flip → `None`; foreign output domain → `None`; beacon/election role-swap never collides. |
| 9 | Small-subgroup / identity / edge keys | HOLDS (vacuous cofactor — Ristretto) | Identity refused at parse (`from_bytes`, `src/vrf.rs:164`) AND at verify (`:525`); garbage `0xFF…` fails decompress; non-canonical high-bit key refuses; identity-R / garbage-R proofs refuse; 256 flat-pattern keys ALL refuse (19/256 parse as ordinary prime-order points — expected, harmless: Ristretto has no cofactor subgroup to smuggle in); zero/`0xFF`/near-zero seeds derive distinct valid keys with no degenerate path. |
| 10 | Non-malleability (mutated proof ⇒ reject; no truncation/extension smuggling) | HOLDS | 512 + 256 single-bit mutants, full-byte flips, R/z halves swap+duplication, cross-proof splices (R_A+z_B, swapped outputs) — all `None`; serde envelope truncations (cuts 1/8/32/64), trailing-garbage extension, empty/null/wrong-shape payloads — all decode-fail (`malleability_…`). |
| 11 | Binding unforgeability (Falcon-signed VRF key) | HOLDS | Wrong-id / wrong-Falcon-key / truncated-sig bindings refuse (in-module + audit tests); attacker-signed victim-id binding refused here. Reduces to Falcon-512 EUF-CMA. |
| 12 | Seed/election-domain separation (VRF seed vs parent-hash seed) | HOLDS | `VRF_ELECTION_DOMAIN ≠ STELL_SORTITION_V5 ≠ VRF_BEACON_DOMAIN` pinned distinct + behaviorally: height/round/output moves the seed; role-swapped beacon/election bytes diverge. |
| UNKNOWN | Side-channel (constant-time scalar ops), fault-injection on signer, PQ-migration of the VRF key itself | UNKNOWN | Out of scope for this battery: requires timing harness / hardware fault model / NIST hash-VRF spec. The VRF key is classical (documented residual in `src/vrf.rs:34-45`); VRF-key compromise biases ONE validator's own ticket (visible, slashable) but cannot forge others'. |

No REAL-bug finding: every refusal path above behaves as specified. (No `CRITICAL`
file:line to report — the construction's single load-bearing gap remains the
already-documented non-uniqueness, slated for the phase-2 ECVRF swap.)

## 2. Grinding quantification (measured + closed form)

Holder-grind model: for fixed `(pk, input)` the holder mints N proofs under N
adversary-chosen nonces (all verify — non-uniqueness) and keeps the lowest
ticket `y = output-as-u128`. Measured with M=128 inputs × N=32 alternates
(deterministic PRF nonces, `grind_scalar` in the test):

| quantity | measured | theory |
|---|---|---|
| outputs minted | 4096 (all verify) | — |
| first-byte χ² (255 df) | 277.1 | 255 (uniform mean) |
| first-byte bin min / max (exp 16.0) | 6 / 31 | Poisson(16): ≈4–29 typical |
| first-bit fraction | 0.4995 | 0.5 |
| mean best-of-32 ticket (fraction of 2¹²⁸) | 0.02784 | 1/33 ≈ 0.03030 |
| p=0.05 honest / best-32 / closed `1-(1-p)^32` | 0.0469 / 0.8125 / 0.8063 | match |
| p=0.25 honest / best-32 / closed | 0.2422 / 1.0000 / 0.9999 | match |
| p=0.50 honest / best-32 / closed | 0.5312 / 1.0000 / 1.0000 | match |

Committee-fairness implication: with per-draw election probability p (from
`lottery_threshold`: p ≈ stake·expected/total), an honest validator lands in
committee with probability p per draw, while a grinding holder lands with
`P_grind(N) = 1-(1-p)^N`. Best-of-N table (closed form, verified against the
measured N=32 row above):

| N (proofs ground) | p=0.05 | p=0.10 | p=0.25 | p=0.50 |
|---|---|---|---|---|
| 1 (honest) | 0.0500 | 0.1000 | 0.2500 | 0.5000 |
| 2 | 0.0975 | 0.1900 | 0.4375 | 0.7500 |
| 3 | 0.1426 | 0.2710 | 0.5781 | 0.8750 |
| 4 | 0.1855 | 0.3439 | 0.6836 | 0.9375 |
| 5 | 0.2262 | 0.4095 | 0.7627 | 0.9688 |
| 8 | 0.3366 | 0.5695 | 0.8999 | 0.9961 |
| 10 | 0.4013 | 0.6513 | 0.9437 | 0.9990 |
| 16 | 0.5599 | 0.8147 | 0.9900 | 1.0000 |
| 25 | 0.7226 | 0.9282 | 0.9992 | 1.0000 |
| 32 | 0.8063 | 0.9657 | 0.9999 | 1.0000 |
| 50 | 0.9231 | 0.9948 | 1.0000 | 1.0000 |
| 64 | 0.9625 | 0.9988 | 1.0000 | 1.0000 |
| 100 | 0.9941 | 1.0000 | 1.0000 | 1.0000 |

Reading: at N=3 a 5%-stake holder already elects at 14.3% (≈2.9× honest); at
N=32 they elect at 80.6% (≈16×); at N=100, 99.4% (≈20×, near-certain).
Grinding is cheap (one base-point mult + two hashes per candidate — the test
mints 4096 in 0.6 s inside a shared suite), so N is bounded only by the
reveal rule: each minted proof is a committable ticket, and only published
outputs advance the beacon — but NOTHING in the Schnorr construction stops a
holder from minting N privately and revealing the best. Under a VRF-lottery
election this converts a small-stake holder into a near-certain committee
member: the sortition-fairness decision must treat best-of-N as the DEFAULT
holder strategy, not an edge case.

## 3. ECVRF comparison (RFC 9381 `ECVRF-EDWARDS25519-SHA512-Elligator2` family)

| Property | This construction (det.-Schnorr) | ECVRF (phase-2 target) |
|---|---|---|
| Unforgeability (no secret ⇒ no proof) | YES (pinned §1 #3) | YES |
| Completeness / determinism | YES | YES |
| Uniqueness (one output per pk+input) | NO — holder mints N valid outputs (§2) | YES (DLEQ binds R to input hash) |
| Self-grinding resistance | NO — `1-(1-p)^N` amplification (§2) | YES (nothing to choose between: one output) |
| Other-grinding resistance (bias victim tickets) | YES (needs victim secret) | YES |
| Key-substitution boundary | Registry/Falcon binding only (proof binds key) | Same (proof binds key; identity is out-of-band) |
| Ciphersuite separation (hash-to-curve, suite IDs) | Ad-hoc tags (distinct but unaudited) | Standardized suite + `hash_to_curve` |
| Batch-verification rules | None (single-verify only) | Defined (batch equation is sound for ECVRF) |
| PQ posture | Classical key + PQ-signed binding (documented residual) | Same (classical VRF key; PQ-native VRF is future work) |
| Audit status | Hand-rolled, reviewed only by these batteries | Audited crate (phase-2 requirement: NOT hand-rolled) |

The ONLY row that changes the consensus decision is uniqueness/self-grinding:
everything this construction does right, ECVRF also does; the one thing it gets
wrong, ECVRF fixes.

## 4. Recommendation: NO-GO for consensus use (conditional)

**Verdict: NO-GO for activating VRF sortition on this construction; GO for
keeping the phase-1 scaffolding exactly as-is (default-off, election
byte-identical, registry inert).**

Conditions for flipping to GO (all required, in order):

1. **Phase-2 ECVRF swap**: replace `vrf_prove`/`vrf_verify` bodies
   (`src/vrf.rs:499`/`518`) with an audited RFC 9381 crate behind the SAME
   signatures; re-run this battery plus the audit battery — the uniqueness
   test MUST flip to "second proof refuses" and §2's best-of-N MUST collapse
   to the honest row before any activation discussion.
2. **Activation as flag-day with 100%-power binding readiness**: every
   validator's `VrfBinding` registered and verified; `VrfActivation` boundary
   published with the binary; pre-`H_vrf` history verifies under v5 forever
   (already the pattern in `PLAN-VRF.md` §4).
3. **Grinding re-analysis post-swap**: with uniqueness, holder best-of-N
   disappears; residual grinding = VRF-key compromise (one validator's own
   ticket, visible/slashable) + beacon-withholding liveness stalls (stall,
   not bias — chain-don't-replace). Re-quantify both before mainnet heights.
4. **UNKNOWN rows closed or accepted in writing**: side-channel/fault posture
   of the signer, and the PQ-migration path for the VRF key itself.

Rationale in one line: the construction is a sound, well-domain-separated,
fail-closed Schnorr proof system that is unfit for lottery election for
exactly one reason — the secret holder chooses among N valid tickets, turning
any stake into near-certain election (§2 table) — and that reason is both
sufficient for NO-GO and fully removed by the planned audited-ECVRF swap.

## 5. Classical status + LaV endgame (FULL-PQ verdict)

ECVRF-EDWARDS25519 is CLASSICAL: Shor breaks the Edwards25519 discrete log and forges arbitrary proofs/outputs, so in the FULL-PQ architecture VRF stays default-off (`VrfActivation::Disabled`, parent-hash draw live) and sortition MUST NOT consume ECVRF output on the PQ path while `VRF_IS_POST_QUANTUM` reads `false` (pinned by `vrf_is_marked_classical_not_post_quantum`); any non-PQ use is LEGACY-ONLY behind a lead-defined opt-in, never a default. The PQ-native endgame is the LaV lattice VRF (`docs/PQ_VRF_LAV_FEASIBILITY.md`): long-term stateless with uniqueness YES under Module-LWR, but ~10.27 KB proofs, unpublished timings, unaudited research code, and 4–6 person-months plus external audit before any consensus wiring — so LaV stays research-only and nothing about the classical verdict changes until an audited, standardized PQ VRF lands.

## 6. Canonical-draw decision (LEAD, 2026-11-03): VRF arming retired
LEAD DECISION: the parent-hash draw is THE canonical sortition mechanism; `STELL_VRF_ACTIVATION_HEIGHT` is retired.
If set it warns loudly and is ignored (`vrf_activation_from_env` always returns `Disabled`): stale configs arm nothing, never panic.
Pinned by `tests/vrf_canonical_draw_tests.rs`: a PQ-enforced run with the VRF module present-but-off elects byte-identically to the parent-hash draw (no VRF output consulted).
The ECVRF module stays, marked classical and off — deletion was rejected (blast radius); a PQ-native VRF stays future work per §5.
