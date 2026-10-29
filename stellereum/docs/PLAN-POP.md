# PLAN-POP — BLS proof-of-possession registry (A7/C2 structural fix)

Status: **PHASE 1 BUILT** (PoP format + verify + accept-new registry parsing
+ metering; startup refusal UNCHANGED). Phases 2–3 specified for a follow-up.

## 1. Problem (verified)

`src/bls.rs` carries real pairing-based BLS12-381 aggregates, but the key
registry (`STELL_BLS_KEYS_FILE` / `STELL_BLS_KEYS`, parsed by
`parse_registry_entries`, `src/bls.rs:631`) holds bare
`<ed25519> <bls-pubkey>` pairs with NO proof-of-possession. A rogue-key
attacker registers `pk*` crafted against honest keys and forges same-message
aggregates, so counting BLS power is unsound — and correctly hard-refused at
startup (`refuse_bls_qc_if_enabled`, `src/bls.rs:497`, called from
`src/main.rs:6646`). Default-off nodes are unaffected; the 100+-signature
Ed25519 path stays authoritative.

## 2. Consensus-breaking surface (exact — by grep, not guessed)

| # | Struct / hash / preimage | File:line | What changes and why |
|---|---|---|---|
| 1 | Registry wire format: `<ed> <bls>` → `<ed> <bls> <pop>` | `src/bls.rs:462,631` | Every entry gains a 96-byte BLS PoP token. File/env plumbing, operator re-registration, and the parse function all change shape. Old binaries ignore a third token (v1 reading); new binaries verify it (phase 2+). |
| 2 | `QcBlsConfig::from_env` + `canonical_keys` | `src/bls.rs:578,603` | Phase 2 resolves keys ONLY for PoP-verified entries; a member missing a valid PoP disables the BLS path per certificate (same fallback posture as a missing member today). |
| 3 | `refuse_bls_qc_if_enabled` gate | `src/bls.rs:497`, `src/main.rs:6646` | Phase 2 REPLACES the unconditional refusal with "refuse unless every registry entry carries a valid PoP" (readiness = `legacy == 0 && rejected == 0`, see §6). Deleting the gate WITHOUT the PoP check re-opens the rogue-key forgery — the plan's bright line. |
| 4 | `QuorumCertificate` BLS envelope (`BLS_QC_MARKER_ID`, `QC_BLS_MAGIC`, `encode/decode_qc_bls_envelope`) | `src/consensus.rs:140,156,162,194` | Bytes UNCHANGED (the envelope already carries sig+bitvector; PoP is registry-side, not certificate-side). What changes is WHEN `bls_path_power` (`src/consensus.rs:2832`) may COUNT: only over PoP-verified keys. Vote envelope `VOTE_BLS_MAGIC` (`src/consensus.rs:131`) likewise unchanged. |
| 5 | Aggregate production (`VoteSet` assembly `src/consensus.rs:2188`, `aggregate_signatures`, `verify_aggregate_signature`) | `src/bls.rs:295,340`, `src/consensus.rs:2188` | Crypto UNCHANGED; the validator-set → key-list binding it verifies against becomes PoP-filtered. No preimage/hash break. |
| 6 | Slashing attribution (`signers_set`, `qc_signed_power`) | `src/consensus.rs:2865`, `src/consensus.rs:1070` | BLS-attributed signers become PoP-verified signers only; unverified entries attribute nobody (already the posture for forged envelopes). |

Tests / golden vectors affected:

* `tests/bls_qc_compat_tests.rs` (all: golden old-cert decode, marker-id, envelope round-trip, vote envelope, `enabled_config` fixture) — phase 2 adds PoP-carrying fixtures + a "legacy entry disables BLS power per certificate" case; v1 vectors keep passing (legacy accepted).
* `src/bls.rs::internal_tests` — extended this change (PoP prove/verify, v2 parse matrix) without touching existing tests.
* `tests/v34_verification_pentest.rs:433`, `tests/pq_audit_closure_tests.rs:332` (`QcBlsConfig { ... }` literals) — phase 2 must NOT add struct fields without updating these literals (reason phase-1 metering uses atomics, §6).
* NOT broken: `vote_sign_bytes`, block hashes, Ed25519 quorum path — PoP never touches a preimage.

## 3. Migration plan (keeps the live chain running)

* **Phase 1 — ACCEPT-NEW + EMIT-OLD (BUILT, this change).**
  `bls_sign_pop` / `bls_verify_pop` / `bls_pop_preimage` (`BLS_POP_DST =
  STELL_BLS_POP_V1`), `parse_registry_entries_v2` (accepts `ed bls pop`,
  verifies, still accepts bare `ed bls` byte-identically to v1; invalid PoP
  → skip + warn, the existing malformed-entry posture), `BlsRegistryStats`
  per-parse counts, process-wide migration counters
  `bls_registry_migration_counts()`. Emission: unchanged (Ed25519 list still
  authoritative; aggregate still ignored at verify when the flag is off, and
  the startup gate still refuses flag-on). Refusal: unchanged. Rollback:
  delete the section — `parse_registry_entries` (v1) is untouched and still
  the only parser `from_env` calls.
* **Phase 2 — accept-new + emit-new (SPECIFIED, follow-up).** (a) Operators
  re-register WITHOUT re-staking: the staking ledger already keys validators
  by Ed25519 id (`ValidatorId`), and the BLS registry is a SEPARATE
  off-ledger map (`BlsKeyRegistry`), so re-registration is "append the PoP
  token for your existing id" — no bond/unbond, no power change, no stake
  migration. Publish a `stellereum keys sign-bls-pop --ed-id …` CLI that
  outputs the third token offline. (b) `from_env` switches to the v2 parser
  (or v1 parser gains the PoP branch — same code, moved); per-entry outcome
  metered. (c) The startup gate becomes PoP-conditional: refuse `STELL_BLS_QC=1`
  UNLESS `rejected == 0 && legacy == 0 && pop_verified == validator count`
  (fail closed on partial migration). Mixed-version: flag-off nodes verify
  through Ed25519 exactly as today (envelope ignored); flag-on+full-PoP nodes
  additionally count aggregates — both accept the same certificates because
  production NEVER strips the Ed25519 list (the strip that realizes wire
  savings waits for phase 3 unanimity).
* **Phase 3 — emit-new + refuse-old (SPECIFIED, follow-up).** At scheduled
  height `H_bls` (coordinated all-validators upgrade, same rule as the
  `STELL_PROPOSER_V1` schedule change): certificates may carry the aggregate
  WITHOUT the full Ed25519 list (wire savings land here), and verifiers at
  `h >= H_bls` REFUSE pre-PoP aggregate formats. Legacy 2-token registry
  lines stop parsing (refuse at load with the operator-facing fix: "re-register
  with PoP"). In-flight pre-`H_bls` certificates verify under the old rule
  (height-gated).

## 4. Activation mechanism

No governance vote: a vote cannot securely activate the rule that secures
vote aggregation. Activation is (a) operator-driven readiness (100% PoP
registry, metered) PLUS (b) a scheduled height `H_bls` for the phase-3
format switch, published with the phase-3 binary. Mixed-version behaviour:
* Phase 1 vs anything: identical bytes, identical verify — full interop.
* Phase 2 mixed: flag-off nodes ignore aggregates (Ed25519 quorum, unchanged);
  flag-on+PoP nodes count them; both converge because the Ed25519 list is
  never stripped in phase 2. A flag-on node WITHOUT full-PoP registry fails
  closed at STARTUP (refusal), never mid-chain.
* Phase 3 at `H_bls`: old nodes halt loudly on stripped certificates
  (expected flag-day); upgraded nodes verify aggregates against PoP keys only.

## 5. PoP format (specified + BUILT verify)

`pop = BLS.Sign_blssk(STELL_BLS_POP_V1 || ed25519_id)`, 96 bytes, third
registry token. Decision record: the PoP MUST be BLS-by-BLS-secret — only
secret knowledge defeats rogue-key forgery, and per the PQ policy a Falcon
signature cannot prove BLS-secret possession. An additional Falcon-512
authorization of the `(ed, bls)` LINK may ship in phase 2 (operator proves
the mapping; defense-in-depth), but it is NOT a substitute for the BLS PoP
verified here. Registry migration needs no re-staking: BLS keys live in the
off-ledger `BlsKeyRegistry` keyed by the UNCHANGED staking `ValidatorId`.

## 6. Aggregate-verification path (what replaces the 100+-sig path)

Unchanged cryptography (`verify_aggregate_signature` pairing identity,
`SignerBitVector` membership, `canonical_keys` order, `bls_path_power`
quorum gate). The ONLY change is the key list it sums over: PoP-verified
registry entries (phase 2+) instead of "any bare pair that parses". The
100+-sig Ed25519 path stays as the fallback AND the phase-2 authority; the
aggregate replaces it on the wire only in phase 3, after unanimous PoP
readiness. Downtime-slash input (`absent_indices` over the bitvector) keeps
working because the bitvector is mandatory in the envelope (unchanged).

## 7. Rollback

* Abort phase 2: unset `STELL_BLS_QC`, or ship a binary restoring the
  unconditional refusal — Ed25519 verification never stopped, so rollback is
  a restart, not a replay. Registry PoP tokens are inert metadata to old code.
* Abort phase 3: only BEFORE `H_bls` (move the height out). AFTER `H_bls`
  stripped certificates, rollback = pre-`H_bls` snapshot + v2 binary —
  standard flag-day cost, published with the schedule.

## 8. What was built vs specced

* BUILT (phase 1, this change): `src/bls.rs` PoP section —
  `BLS_POP_DST`, `bls_pop_preimage`, `bls_sign_pop`, `bls_verify_pop`,
  `BlsRegistryStats`, `parse_registry_entries_v2`,
  `bls_registry_migration_counts`; unit tests
  (`pop_proves_possession_and_binds_the_ed_identity`,
  `registry_v2_accepts_pop_and_legacy_and_refuses_forged_pop`).
  `refuse_bls_qc_if_enabled`, `QcBlsConfig`, `from_env`: untouched.
* SPECCED (follow-up): v2 wiring into `from_env`, PoP-conditional startup
  gate, operator re-registration CLI (no re-staking), phase-3 strip at
  `H_bls`.
