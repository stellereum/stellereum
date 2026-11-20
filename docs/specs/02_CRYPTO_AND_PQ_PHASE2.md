# 02 — Crypto & Post-Quantum (HDAE Phase-2, code truth)

Verified on the 2026-11-18 tree (base HEAD `0fdf1eefc` plus the day's in-flight
edits; line numbers match that tree), after the FULL-PQ wipe and the module
split. Classical signature paths are deleted: there is no `bls.rs`, no
ECVRF activation, and no `STELL_PURE_PQ` switch on the node. Every `file:line`
below was re-grepped on this tree; anything that is no longer resolvable is
marked `STALE — see <path>`.

> **Ruleset snapshot — historical for constants.** Verified under ruleset
> **v2**; the CN-VRF height windows shown here (7 200 / 450 / 360) are the v1
> values, not current. Ruleset v6 is current (`FORK_ID = 0x0f584a46`); current
> values are `EPOCH_LEN = 30_000`, `V3_SEGMENT_LEN = 1_875`,
> `V3_COMMIT_LOOKAHEAD_BLOCKS = 682` (`docs/RULESET_V6.md`; unchanged since v5).

Sources: `stellereum/src/post_quantum.rs`, `pq_registry.rs`, `vrf.rs`,
`cn_vrf.rs`, `minroot_vdf.rs`, `staking.rs`, `wallet_signing.rs`,
`stellereum/Cargo.toml`.

## 1. Falcon-512 (FIPS 206)

- Sizes pinned: pubkey 897 B (`post_quantum.rs:127`), sig 666 B (`:136`);
  ML-DSA-44 sizes 1312 B / 2420 B are listed but unusable (`:128,:137`).
- Lattice params: `FALCON_MODULUS_Q 12289` (`:140`), `FALCON_N 512` (`:141`),
  `FALCON_NORM_BOUND_SQ 34034726` (`:142`).
- Verifier: `verify_pq_signature` (`:534`), Falcon path `verify_falcon512`
  (`:2213`); linked C archive via `pqcrypto-falcon 0.4.1`
  (`stellereum/Cargo.toml:46`, link note `:43-45`).
- Verify-only posture: node links the Falcon C archive for verify; the
  in-module FIPS-206 signer exists for operator tooling. There is no classical
  fallback anywhere.
- CN-VRF re-pins the same sizes: `CNVRF_PK_LEN` / `CNVRF_PI_LEN`
  (`cn_vrf.rs:77-79`).

## 2. Pure-PQ enforcement points

- `is_pure_pq_enforced()` (`post_quantum.rs:89`): on the node the override is
  installed as `Some(true)` (`node/consensus_driver.rs:94`), so the
  `STELL_PURE_PQ` env is parsed-and-ignored with a WARN (`:78`). It is a
  library/sim switch only — **do not document it as a node switch**.
- Programmatic override `set_pure_pq_override` (`post_quantum.rs:56`).
- Mempool: non-PQ envelopes are refused (`mempool.rs`; FULL-PQ admission).
- QC verify: non-post-quantum entries are rejected with no fallback
  (`consensus/types.rs:1859-1861`).
- ML-DSA-44 fail-closed: `from_id(3)` is unknown/refused (`post_quantum.rs:184-197`),
  `is_disabled()` returns true for it (`:206-208`).

## 3. Classical inventory pointer

- `docs/CLASSICAL_INVENTORY.md:1` is the classical-use registry. The tree
  still carries transport/ECC dependencies that are NOT consensus signature
  schemes: `ed25519-dalek` (`stellereum/Cargo.toml:13`) and `argon2` (`:37`).
  `bls12_381` is **gone**; `x25519-dalek` is gone from the core crate.
- infnode's PQ transport is the live PQ path (Falcon frame auth + ML-KEM-768
  KEX); stale KEX-verdict prose was corrected in `pq_transport.rs:8`.
- `ml-kem 0.3` is a direct `infnode` dependency
  (`infnode/crates/infnode/Cargo.toml:34`) with Wycheproof KATs
  (`infnode/crates/infnode/tests/kem_kat_tests.rs`). The module is still NOT
  declared in `infnode/src/lib.rs` (mod list `:4-17`), so `pq_transport` is
  UNWIRED: the crate and KATs exist, no node path calls them.

## 4. Classical markers (do not present as PQ)

- **BLS: DELETED.** There is no `bls.rs`, no `DEFAULT_BLS_ACTIVATION_HEIGHT`,
  and no BLS QC marker. Any pointer to `bls.rs` is STALE — see
  `stellereum/src/consensus/` for the PQ-only QC path.
- **ECVRF: DELETED.** `vrf.rs` is 133 lines of pure sortition MATH only
  (`vrf.rs:1-22` header): no key material, no registry, no environment reads,
  no `VrfActivation`, no `STELL_VRF_ACTIVATION_HEIGHT`. The live committee
  election is the canonical parent-hash draw (`consensus/sortition.rs:404,425`).
  Any pointer to `vrf.rs:128` / `STELL_VRF_ACTIVATION_HEIGHT` is STALE.
- Domains that remain are CN-VRF's, not ECVRF's: see §5.

## 5. CN-VRF (v1 + v3 + MinRoot PQ-VDF) — WIRED

- Spec: `docs/PQ_CN_VRF_SPEC.md:1`.
- v1 sandbox primitives: `EPOCH_LEN 30_000` (`cn_vrf.rs:69`); DSTs
  `STELL_CNVRF_COMMIT_V1` / `COMMIT_SIG_V1` / `OPEN_V1` / `BETA_V1`;
  `cnvrf_commit` (`:381`), `cnvrf_verify` (`:491`), commit state
  (`:655,:687`); nonce custody 0600.
- CN-VRF v3 (`cn_vrf.rs:1009+`): 16-segment 48-byte `BLAKE3-XOF-48` reverse
  hash-chain (`V3_LINK_LEN 48` `:1013`, `V3_SEGMENTS 16` `:1015`,
  `V3_SEGMENT_LEN 1_875` `:1021`; `16 × 1_875 = EPOCH_LEN`);
  `V3_COMMIT_LOOKAHEAD_BLOCKS 682` (`:1032`); `CommitCarrierV3`
  (`COMMIT_CARRIER_V3_LEN` `:1025`); bounded reveal verify
  `cnvrf_v3_verify_reveal` (`:1466`); `CnVrfV3State` (`:1519`);
  deterministic `epoch_raw_seed` fallback (`:1707`).
- Activation & abort accounting: `CNVRF_V3_ACTIVATION_HEIGHT`
  (`consensus/sortition.rs:552`, default `u64::MAX` = dormant),
  `CNVRF_V3_EPOCH_LEN 30_000` (`:669`), sortition entry points
  (`:601,:619`); dedicated non-vote-resettable abort slashing in `staking.rs`
  (`CNVRF_ABORT_SLASH_BPS`, `CNVRF_ABORT_THRESHOLD`,
  `CNVRF_ABORT_RECOVERY_STREAK`, `CnVrfAbortState` + `slash_cnvrf_abort`).
- **The old "sandbox, zero callers, unwired" claim is FALSE now.** `cn_vrf`
  is imported by `runtime/mod.rs:621-629`, `runtime/anchors.rs:101-209`,
  `runtime/apply.rs:1001-1078`, `commitment.rs:1919+`, `storage.rs:5106`,
  `sync.rs:2864`. The v3 sortition gate is production code, currently OFF.
- Off-tick `VdfLane` (`runtime/anchors.rs:265,274,744`;
  `runtime/lanes.rs` VdfLane) evaluates the checkpointed MinRoot PQ-VDF
  (`minroot_vdf.rs`).

## 6. PQ registry + rotation

- `PQ_ROTATION_DELAY_HEIGHTS 30_000` (`pq_registry.rs:105`);
  `PQ_KEY_HISTORY_LIMIT 2` (`:110`); `PQ_MAX_KEY_BYTES = MLDSA44_PUBKEY_LEN`
  (`:122`); announce DST `STELL_PQ_ROTATE_V1` (`:126`).
- The old "`PQ_MAX_KEY_BYTES = HYBRID_PUBKEY_LEN 929`" claim is STALE: the
  hybrid scheme is removed.

## 7. `mev_pq_plan.rs` — test-only posture

- `#[cfg(test)] mod mev_pq_plan` (`lib.rs:35-37` with GATE comment); 335
  lines; header self-describes UNWIRED, `std`-only mechanics model; zero
  production callers. Its domains/API (`pq_plan_digest`, `pq_plan_commit`,
  `pq_plan_open_verify`, `pq_plan_beta`, `pq_plan_transcript`) remain
  test-only; line numbers from the pre-split pass are STALE — read
  `stellereum/src/mev_pq_plan.rs` directly.
- Ranked replacement discussion is a design note only; the live MEV transport
  is PQ already (classical packages refused at every height,
  `mev_epoch.rs:990-1006`).

## 8. KEM harness / benches (no invented numbers)

- `STALE — see stellereum/benches/ and stellereum/tests/`. The old text cited
  `benches/privacy_batch.rs` and `tests/privacy_pq_tests.rs`, which no longer
  exist. No static before/after ns/tx values are pinned anywhere; throughput
  is runtime-only.
- `tests/pq_gates_staking_light_tests.rs` and
  `tests/privacy_pq_tests.rs` — the latter is gone; the gate matrix that
  remains lives in `stellereum/tests/` (grep for `pq_gates`).
- `ml-kem` KATs: §3 above (1184/1088/768/1568 B vectors in
  `kem_kat_tests.rs`); measured numbers are not claimed here.
