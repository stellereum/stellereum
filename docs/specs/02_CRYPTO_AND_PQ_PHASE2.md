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
