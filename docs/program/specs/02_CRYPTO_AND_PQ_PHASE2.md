# 02 — Crypto & Post-Quantum (HDAE Phase-2, code truth)

Source files: `stellereum/src/post_quantum.rs`, `pq_registry.rs`, `bls.rs`,
`vrf.rs`, `cn_vrf.rs`, `wallet_signing.rs`, `stellereum/Cargo.toml`.
Pointers: `docs/CLASSICAL_INVENTORY.md:1`, `docs/PQ_CN_VRF_SPEC.md:1`.

## 1. Falcon-512 (FIPS 206)

- Sizes pinned: pubkey 897 B (`post_quantum.rs:103`), sig 666 B (`:109`);
  hybrid 929 B (`:105`) / 730 B (`:111`); Ed25519 32 B (`:102`) / 64 B (`:108`).
- Lattice params: `FALCON_MODULUS_Q 12289` (`:114`), `FALCON_N 512` (`:115`),
  `FALCON_NORM_BOUND_SQ 34034726` (`:116`).
- Verifier: `verify_pq_signature` (`:520`), Falcon path `verify_falcon512` (`:2319`);
  FIPS-206-compliant keygen+signer block (`:1190`); linked C archive via
  `use pqcrypto_falcon as _` (`:23`), dep `pqcrypto-falcon 0.4.1`
  (`stellereum/Cargo.toml:55`).
- Verify-only posture: node links the Falcon C archive for verify; keygen/signer
  code present in-module (`:1190-1222` header — FIPS-206 `ffSampling` signer,
  C entry points for caller-seeded randomness; operator key tooling = this
  in-module signer, linked archive via `use pqcrypto_falcon as _` `:23`).
- CN-VRF re-pins the same sizes: `pk == 897`, `pi == 666` (`cn_vrf.rs:67-69`).

## 2. Pure-PQ enforcement points

- Switch: `is_pure_pq_enforced()` (`post_quantum.rs:71-90`); env `STELL_PURE_PQ`
  (`:80-84`, values `1`/`true`/`always`); programmatic override
  `set_pure_pq_override` (`:48-56`, atomic `:25`, test thread-local `:39-41`).
- Mempool: non-PQ `pq_envelope` refused (`mempool.rs:1844-1859`,
  message `Pure PQ mode: classical non-PQ transactions rejected` `:1850`).
- QC verify: classical BLS/Ed25519 paths refused under pure-PQ
  (`consensus.rs:2851-2854`).
- Batch-mirror contract: every batched screen MUST branch on the flag and fall
  back to scalar verify (`post_quantum.rs:65-70`).
- ML-DSA-44 fail-closed: `from_id(3)` refuses loud (`post_quantum.rs:159-171`),
  `is_disabled` gate (`:173-179`), sizes 1312/2420 listed but unusable
  (`:104,:110`).

## 3. Classical inventory pointer

- `docs/CLASSICAL_INVENTORY.md:1` is the classical-use registry (ed25519,
  secp256k1, X25519, P-256, BLS12-381, RSA/DSA/DH). Tree deps confirm classical
  crates: `ed25519-dalek` + `x25519-dalek` (`stellereum/Cargo.toml:13-14`),
  `bls12_381 0.9` (`:41`), `argon2 0.5` (`:46`); infnode workspace also carries
  ed25519/x25519 (confirmed `infnode/Cargo.toml:17,40`,
  `infnode/crates/infnode/Cargo.toml:14,32`; inventory `:17-19`).
- No PQ KEM op in tree: `Cargo.lock` carries no `ml-kem`/`mlkem`/`kyber` package
  (verdict `pq_transport.rs:60-70`); only ML-KEM-768 framing consts in parked
  `mev_v4.rs:84-112` (dead engine, `STELL_MEV_V4` default-off) + an
  explicitly-unavailable rank-1 KEM entry (`pq_transport.rs:391-396`, test-pinned
  `:639-641`); PQ sigs present. Inventory `:21` corroborates.

## 4. Classical markers (do not present as PQ)

- BLS: `PUBLIC_KEY_LEN 48` (`bls.rs:72`), `SIGNATURE_LEN 96` (`:74`),
  `BLS_IS_POST_QUANTUM = false` (`:80`), activation-gated
  `DEFAULT_BLS_ACTIVATION_HEIGHT 10000` / `is_bls_active` (`:83-86`).
  No-PoP structural status: `parse_registry_entries` accepts any non-identity
  G1 with NO proof-of-possession — rogue-key rationale at `bls.rs:527-531`;
  strict-PoP parse opt-in via `STELL_BLS_POP_REQUIRED` (`:508-518`).
- ECVRF: Edwards25519 ECVRF per RFC 9381 (`vrf.rs:21-23`); explicitly
  CLASSICAL/legacy/off-only (`:56-73`); activation env
  `STELL_VRF_ACTIVATION_HEIGHT` (`:128`); default Disabled (runtime gate
  `runtime.rs:1677` comment). Deterministic-Schnorr construction: "legacy
  Schnorr proof hashes" domain `vrf.rs:106`, output-hash domain `:113`,
  phase-1 envelope note (`R || z`, 80 B) `:145`.
- Domains: `VRF_BEACON_DOMAIN` (`vrf.rs:94`), `VRF_SCALAR_DOMAIN` (`:101`),
  `VRF_BINDING_DST` (`:104`), `VRF_PROOF_DOMAIN` (`:111`),
  `VRF_OUTPUT_DOMAIN` (`:118`), `VRF_ELECTION_DOMAIN` (`:124`).

## 5. CN-VRF pointer

- Spec: `docs/PQ_CN_VRF_SPEC.md:1` (status SPEC ONLY at time of writing;
  since then sandbox code landed — see next).
- Sandbox: `cn_vrf.rs:1-4` (pure module, KATs, NO consensus wiring);
  `EPOCH_LEN 7200` (`:58`); DSTs `STELL_CNVRF_COMMIT_V1` / `OPEN_V1` / `BETA_V1`
  (`:61-65`); nonce custody 0600 (`:633-646`, load `:681-726`).
- Live-protocol wiring status: code truth is `cn_vrf.rs` sandbox + spec pointer;
  no activation-height const exists in `cn_vrf.rs` (only `EPOCH_LEN 7200` at
  `:58`); the sortition gate only knows `vrf::VrfActivation`
  (`consensus.rs:1080-1086`); zero `cn_vrf::` callers outside `cn_vrf.rs`.

## 6. PQ registry + rotation

- `PQ_ROTATION_DELAY_HEIGHTS 7200` (`pq_registry.rs:97`, ≈6h at 3s blocks `:86`);
  rationale + test pin vs `COMMISSION_EFFECT_DELAY_HEIGHTS` (`:88-96`).
- `PQ_KEY_HISTORY_LIMIT 2` (`:106`); `PQ_MAX_KEY_BYTES = HYBRID_PUBKEY_LEN 929`
  (`:115`); announce DST `STELL_PQ_ROTATE_V1` (`:119`); error enum fail-closed
  (`:127-144`).

## 7. CN-VRF API surface (sandbox, code truth 2026-11-02)

- Sandbox header + purity contract (`cn_vrf.rs:1-16`): pure fns + KATs only,
  NO consensus/staking imports, no activation-height const; spec pointer
  `docs/PQ_CN_VRF_SPEC.md:1`.
- `EPOCH_LEN 7200` (`cn_vrf.rs:58`, O1 == `PQ_ROTATION_DELAY_HEIGHTS`);
  DSTs `CNVRF_COMMIT_DST`/`OPEN_DST`/`BETA_DST` (`:61-65`); lens
  `CNVRF_PI_LEN 666` / `CNVRF_PK_LEN 897` (`:67-70`, re-pin Falcon-512 sizes).
- API: `shake256_32` (`:114`), `shake256_xof` (`:122`),
  `commit_preimage_bytes` (`:174`), `open_message_bytes` (`:192`),
  `beta_preimage_bytes` (`:212`), `commit_hash` (`:229`),
  `CommitCarrier`/`RevealCarrier` (`:249,:269`, carriers `:90,:92`),
  `cnvrf_commit` (`:300`), `cnvrf_open` (`:325`), `cnvrf_beta` (`:350`),
  `cnvrf_verify` (`:383`), `cnvrf_verify_carrier` (`:425`),
  `cnvrf_verify_with_resolver` (`:461`).
- Epoch/state helpers: `epoch_of_height` (`:490`), `epoch_start_height`
  (`:495`), `first_usable_epoch` (`:502`, O9 waits one full epoch),
  `CommitmentRecord` (`:512`), `cnvrf_commit_state` (`:545`, O10 max-one-pending,
  only `current_epoch+1`), `cnvrf_mark_revealed` (`:579`),
  `cnvrf_expire_before` (`:600`), `cnvrf_draw_absence` (`:618`, O5 maps absence
  to existing downtime path); nonce custody 0600 `save/load/parse`
  (`:638,:662,:681`, O6 mirrors `vrf.rs:360-421`).
- Sandbox status VERIFIED: zero `cn_vrf::` callers in `stellereum/src/` by grep
  (only definitions in `cn_vrf.rs` + `stellereum/tests/cn_vrf_tests.rs:8,293`);
  live sortition gate knows only `vrf::VrfActivation`
  (`consensus.rs:1080-1086`); `cn_vrf` IS declared `pub mod` (`lib.rs:9`) but
  unwired (no production call site).

## 8. `mev_pq_plan.rs` — test-only posture + ranked replacement

- Posture: `#[cfg(test)] mod mev_pq_plan` (`lib.rs:31` with GATE comment
  `test builds only, never production surface`); header self-describes UNWIRED,
  `std`-only mechanics model, KATs via `rustc --test` (`mev_pq_plan.rs:1-7`);
  zero `mev_pq_plan::` callers in tree by grep (only `lib.rs:31` decl).
- Domains: `PQ_PLAN_COMMIT_DOMAIN` (`:82`), `PQ_PLAN_BETA_DOMAIN` (`:84`),
  `PQ_PLAN_TRANSCRIPT_DOMAIN` (`:86`); model digest `pq_plan_digest` (`:109`),
  `pq_plan_commit` (`:133`), `pq_plan_open_verify` (`:141`),
  `pq_plan_beta` (`:154`), `pq_plan_transcript` (`:169`) +
  `pq_plan_transcript_verify` (`:178`); KATs `#[cfg(test)]` (`:190-315`).
- Ranked replacement (honest fit, `:45-68`): RANK-1 Falcon-authenticated PQ-KEM
  transport swap (keep Feldman VSS + Ristretto threshold, replace only X25519
  package encryption `mev_epoch.rs:1094-1136` + Falcon-sign contributions);
  RANK-2 Falcon-signed commit-reveal per CN-VRF pattern for epoch seed only
  (this file prototypes RANK-2 shape — KAT-testable in `std` today);
  RANK-3/REJECTED pure hash-DRB (no threshold-decryption property).
  Design doc mirror: `docs/MEV_PQ_PLAN.md`.

## 9. ML-KEM crate + KEM tests + UNWIRED verdict

- Crate: `ml-kem = "0.3"` direct dep of `infnode`
  (`infnode/crates/infnode/Cargo.toml:36`); locked `ml-kem 0.3.4`
  (`stellereum/Cargo.lock:1580-1582`, deps `hybrid-array/kem/module-lattice`
  `:1584-1589`); pulled into `stellereum/Cargo.lock` via `infnode 0.1.0`
  (`:1327-1350` lists `"ml-kem"` under `infnode` deps).
- Note on stale verdict text: `pq_transport.rs:60-70` KEX VERDICT (dated
  2026-11-02) states `Cargo.lock` holds NO `ml-kem` package — that sentence is
  STALE as of the `infnode` direct dep above; the UNWIRED conclusion still
  holds (next bullet). Do not cite `:60-70` package-absence line as current.
- KEM tests (Wycheproof-pinned, `std`-runnable): published vector
  `mlkem_768_test.json` group 1 tcId 2
  (`infnode/crates/infnode/tests/kem_kat_tests.rs:20-24,40-70`);
  KATs `mlkem768_wycheproof_kat_keygen_ek` (`:144`, ek 1184 B `:148`),
  `mlkem768_wycheproof_kat_decap` (`:153`, ct 1088 B `:156`),
  `mlkem768_roundtrip_fixed_seed_deterministic_encap` (`:171-187`),
  `mlkem768_tampered_ciphertext_implicit_rejection` (`:194`),
  `mlkem512_roundtrip_fixed_seed` (`:218`, ct 768 B `:223`),
  `mlkem1024_roundtrip_fixed_seed` (`:233`, ct 1568 B `:238`).
- UNWIRED: `pq_transport` is NOT declared in
  `infnode/crates/infnode/src/lib.rs` (mod list `config/dht/federation/keyring/
  log/mailbox/metrics/migration/node/proto/reputation/rewards/services/totp` —
  no `pq_transport`); machine-checked by `pqplan_unwired_proof`
  (`pq_transport.rs:734-770`, asserts `lib.rs` + `node.rs` reference neither
  `pq_transport` nor `PqPlan`). `stellereum` PQ-KEM framing consts remain parked
  in dead engine `mev_v4.rs:84-115` (`MLKEM768_PUBLIC_KEY_SIZE 1184`,
  `CIPHERTEXT_SIZE 1088`, magics `MLKEM768_PK_MAGIC/CTXT_MAGIC/SHR_MAGIC`).

## 10. KEM-KAT / privacy_pq / pq-gates harness (no invented numbers)

- No static before/after ns/tx values exist in tree (grep over
  `stellereum/benches/*` + `stellereum/tests/*` finds only harness print
  formats, e.g. `[bench][...] ... ns/op` at `benches/privacy_batch.rs:49-56`,
  `benches/packing.rs:53-66`, `benches/fee_path.rs:168`; measured numbers are
  runtime-only). All throughput claims below are therefore HARNESS-EXISTENCE
  claims, not measurements — UNVERIFIED static count added: 0.
- `privacy_batch` bench (`benches/privacy_batch.rs:1-16`): scalar-vs-batched
  `openings`/`conservation`/`range` + `bitproof_reference_vs_msm` (`:94-155`);
  prints `[bench][privacy_batch][<item>] n=<size> scalar=<ns> batch=<ns>
  speedup=<x>` (`:49-56`) via `time_ns_per_op` (`:35-41`).
- `privacy_pq_tests.rs` (`stellereum/tests/privacy_pq_tests.rs:1-4`): default
  mode honest flow unchanged (`:95-112`), enforced mode refuses all
  Ristretto ops (`:141-222`, `privacy_pq_refused` mirror `:36-55`).
- `pq_gates_staking_light_tests.rs` (`:1-4` mirrors gate rows P2-10/P2-11/P2-16):
  ED-fallback present w/o enforcement (`:130`), refused under pure-PQ (`:145`),
  slash ED-refused/Falcon-slashed matrix (`:180-312`, `BURN_5PC 250*STELL`),
  light-quorum ED-counts/Falcon-counts/empty matrix (`:321-383`).
