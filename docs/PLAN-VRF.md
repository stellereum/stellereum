# PLAN-VRF — VRF sortition (A6/C1 structural fix)

Status: **PHASE 1 WIRED, HEIGHT-GATED** (deterministic-Schnorr proofs + election seed plumbing behind `STELL_VRF_ACTIVATION_HEIGHT`, default off; pre-activation output byte-identical; call sites pinned Disabled pending phase-3 threading).
Phases 2–3 are specified below for a follow-up.

## 1. Problem (verified)

`derive_sortition_committee` (`src/consensus.rs:747`) seeds the draw with
`sortition_seed(prev_block_hash, height, round)` (`src/consensus.rs:826`,
domain `STELL_SORTITION_V5`, `src/consensus.rs:819`). The parent hash makes
the committee unknowable in advance, but the parent's proposer CHOOSES the
parent bytes, so every candidate parent hash is a fresh sortition draw.
Grinding cost for one target seat at N=100/k=64 is ~1.56 BLAKE3 draws
(~microseconds on a GPU — pinned by
`vrf::tests::grinding_cost_proves_parent_hash_is_not_a_security_boundary`).
The network-anchored quorum (`pq_micro_required_power`,
`src/consensus.rs:691`) is the current mitigation, not a fix: it bounds what
a ground committee can finalize, but the grinding surface itself stays open.

## 2. Consensus-breaking surface (exact — by grep, not guessed)

Changing election to a VRF lottery breaks consensus on purpose at activation.
Every item below changes bytes, hashes, or verification — mixed-version nodes
disagree on all of them, which is why activation is a flag-day height (§4):

| # | Struct / hash / preimage | File:line | What changes and why |
|---|---|---|---|
| 1 | `PqMicroCertificate.sortition_parent` semantics + `QC_UQC_MAGIC` (`STELL_UQC_PQ_V5_`) | `src/consensus.rs:393,430` | Phase 3 replaces "parent hash the committee was elected with" by "VRF seed `beacon_{h-1}` the lottery was drawn from". New magic `STELL_UQC_PQ_V6_` (V5 envelopes stop decoding as V6). |
| 2 | `derive_sortition_committee` + `sortition_seed` + `SORTITION_DRAW_DOMAIN` | `src/consensus.rs:747,819,826` | The draw becomes `ticket = VRF_output mod total_power` per validator (local lottery, threshold `vrf::lottery_threshold`) instead of the central stake-weighted shuffle. Old seeds recompute different committees. |
| 3 | `verify_micro_cert` / `micro_cert_valid_signers` | `src/consensus.rs:2488,2603` | Verifier checks VRF proofs (`proof verifies under registered vrf_pk`, `ticket < threshold`) instead of re-running the central draw; committee membership is proof-declared, not recomputed. |
| 4 | `QuorumCertificate.binds_to_parent` pin | `src/consensus.rs:2766` | Replaced by a seed pin: certificate must name `beacon_{h-1}` of the chain it finalizes (recomputed locally via `vrf::beacon_next` chain). Old parent-pin checks fail on new certificates and vice versa. |
| 5 | Gossip vote path (`Vote`, `VoteSet::add`, certificate assembly ~`src/consensus.rs:2188`) | `src/consensus.rs:1177,2180` | Votes carry a VRF proof envelope beside the Ed25519/Falcon halves (accept-new in phase 2); certificate assembly collects proofs per ticket-winner. Old nodes see a longer `signature` blob and fail closed. |
| 6 | Remote-signer preimage contract | `src/remote_signer.rs:54,285` | `vote_sign_bytes` UNCHANGED (VRF ticket is over the same message); remote signers additionally return the VRF proof bytes for the same preimage. No preimage break — deliberate. |
| 7 | `Block::compute_hash` | `src/sharding.rs:5341` | UNCHANGED by design: election affects WHO signs, never the block bytes. (If the header ever commits the beacon, that is a separate, listed change — not in this plan.) |

Tests / golden vectors that break at phase-3 activation (must be re-pinned then):

* `src/consensus.rs` unit tests: `sortition_*` (`~5598–5687`), every `uqc`/`micro_cert` test calling `derive_sortition_committee` (`~5786,5866,6002,6377`).
* Integration: `tests/pq_uqc_power_quorum_tests.rs`, `tests/consensus_audit_hardening_tests.rs:301,327`, `tests/pure_pq_enforcement_tests.rs:123`, `tests/v34_verification_pentest.rs:354,414`, `tests/p3_byzantine_pentest.rs:793,799`, `tests/bls_qc_compat_tests.rs` (envelope magic bump side).
* Golden vectors: any fixture embedding `STELL_UQC_PQ_V5_` bytes or a v5 `sortition_parent`.
* NOT broken: `vote_sign_bytes` / `STELLEREUM_BFT_VOTE_V2` vectors, `Block::compute_hash` / `STELLEREUM_BLOCK_V3` vectors, proposer schedule `STELL_PROPOSER_V1` (unchanged in this plan).

## 3. Migration plan (keeps the live chain running)

* **Phase 1 — ACCEPT-NEW + EMIT-OLD (BUILT, this change).** New module
  `src/vrf.rs`: `VrfSecret`/`VrfPublicKey` (Ristretto255, lives alongside the
  Falcon key), `VrfBinding` (Falcon-512 signature over
  `STELL_VRF_BINDKEY_V1 || validator_id || vrf_pk`), `VrfRegistry`
  (verified-insert only), `beacon_genesis`/`beacon_next` (BLAKE3 chain),
  `lottery_threshold` (128-bit stake-weighted threshold math),
  `expected_draws_to_include_member`/`expected_draws_to_capture_seats`
  (grinding analysis), atomic `vrf_bindings_registered` meter. Emission: none
  (no vote/certificate/block byte changes). Refusal: none (registry is not
  consulted). Rollback: delete the module — nothing reads it.
* **Phase 2 — accept-new + emit-new (SPECIFIED, follow-up).** (a) Add audited
  ECVRF crate (RFC 9381 family; NOT hand-rolled) and implement
  `vrf_prove(secret, seed_h) -> (output, proof)` /
  `vrf_verify(vrf_pk, seed_h, output, proof)` in `src/vrf.rs`. (b) Gossip:
  votes carry the VRF proof envelope beside existing halves; verifiers
  decode+verify+meter, election STILL uses the parent-hash draw (proofs do
  not count yet — old nodes ignore the envelope bytes? NO: old nodes fail
  closed on longer signatures, so phase 2 still needs all-validators
  upgrade for gossip; the SAFETY property is that proofs never decide
  anything in phase 2). (c) Operators register `VrfBinding`s on-chain or via
  the key-registry file; readiness = bindings for 100% of voting power.
  Mixed-version: phase-2 nodes accept phase-1 votes (no envelope) and
  phase-2 votes (envelope verified, election weight unchanged); phase-1 nodes
  reject phase-2 vote bytes loudly — so phase 2 is a coordinated upgrade,
  but a SAFE one (no fork: both elect the same committee from the same
  parent hash).
* **Phase 3 — emit-new + refuse-old (SPECIFIED, follow-up).** At scheduled
  height `H_vrf` (same mechanism as §4): election switches to the lottery
  (`ticket < lottery_threshold`), certificates carry `beacon_{h-1}` + proofs
  under magic `V6`, `binds_to_parent` becomes the seed pin, and verifiers
  REFUSE v5-parent-hash committees at `h >= H_vrf`. In-flight pre-`H_vrf`
  certificates verify under v5 rules (height-gated, like every other
  activation in this codebase).

## 4. Activation mechanism

Scheduled height `H_vrf`, published with the phase-3 binary (governance
announces, operators upgrade; no on-chain vote — a vote cannot securely
activate the rule that makes votes ungrindable). Mixed-version behaviour:
* Phase 1 vs anything: identical election bytes — full interop.
* Phase 2 mixed with phase 1: phase-1 nodes LOUDLY reject phase-2 vote
  bytes (fail closed, no fork); chain liveness needs a supermajority on the
  new binary, same as every envelope change in this codebase
  (`VOTE_BLS_MAGIC`, `VOTE_FALCON_MAGIC` precedent).
* Phase 3 at `H_vrf`: pre-`H_vrf` history verifies under v5 forever
  (height-gated verify); at `h >= H_vrf` old nodes halt on the new election
  (expected, loud) while upgraded nodes finalize — the standard flag-day.

## 5. Seed evolution (specified)

`beacon_0 = beacon_genesis(chain_id)`; `beacon_h = beacon_next(beacon_{h-1},
vrf_output_h)` where `vrf_output_h` is the winning ticket's VRF output for
height `h` (lowest ticket wins ties by `validator_id` order). Lottery seed
for height `h+1` is `beacon_h`. Withholding a reveal stalls that height
instead of re-rolling the seed (chain, don't replace).

## 6. Grinding analysis (pinned in code)

Cost to bias ONE committee seat under the CURRENT scheme:
`E[draws] = n/k` (`vrf::expected_draws_to_include_member`) — 1.56 draws at
N=100/k=64, i.e. free. Under the phase-3 lottery the attacker's search buys
nothing: tickets are `VRF_sk(seed)` — unknowable AND unforgeable without the
victim's secret, and the seed chains published outputs only. Residual:
VRF-key compromise biases ONE validator's own ticket (visible, slashable);
mitigated by the Falcon-signed binding + rotation with the Falcon key.

## 7. Rollback

* Abort phase 2: stop emitting proofs (flag off); v5 election never changed —
  full rollback, no state to unwind (registry rows are inert metadata).
* Abort phase 3: only possible BEFORE `H_vrf` (ship a binary with `H_vrf`
  moved out). AFTER `H_vrf` finalized blocks, rollback = replay from a
  pre-`H_vrf` snapshot with a v5 binary — the standard flag-day cost,
  published with the schedule, never improvised.

## 8. What was built vs specced

* BUILT (phase 1, this change): `src/vrf.rs` — key types, Falcon-signed
  binding + verified registry, beacon chain math, threshold math, grinding
  analysis, metering; unit tests in-module (`cargo test --lib vrf::`).
  Activation/mixed-version/rollback for phases 2–3 are specified here, not
  coded. Election, votes, certificates, block hashes: untouched.
* SPECCED (follow-up): ECVRF prove/verify (audited crate), gossip envelope,
  operator re-registration, `V6` election switch at `H_vrf`.
