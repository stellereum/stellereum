# 02 — Crypto & Post-Quantum (HDAE canonical, 2026-10-29)

Source of truth in code: `stellereum/src/post_quantum.rs`,
`wallet_signing.rs`, `stellereum/Cargo.toml`.

> **Updated for the FULL-PQ wipe (2026-11-20).** The former `bls.rs`
> (BLS12-381 aggregate certificates) was deleted with the classical excision;
> validator votes are Falcon-512-only (`Vote::verify_uncached`) and Ed25519
> survives **only as the 32-byte validator identity/voter id**, never as a
> vote or transaction signature. See `docs/specs/02_CRYPTO_AND_PQ_PHASE2.md`
> for the current module-level map.

## Algorithm set

| Use | Algorithm | Notes |
|---|---|---|
| Validator/consensus signatures | Falcon-512 (FIPS 206) | Falcon-only: `Vote::verify` refuses a vote without a verifying Falcon half. Ed25519 is the voter id, not a signature |
| Post-quantum signatures | Falcon (FIPS 206, via `pqcrypto-falcon`, PQClean C archive) | All 4 live validators hold full PQ key sets |
| Aggregate certificates | Falcon µQC signatures (no BLS) | BLS12-381 and its pairing dependency were deleted; there is no aggregate/pairing path |
| Key exchange (mail/overlay) | X25519 + ChaCha20Poly1305 | infnode/infmail |
| Hashing | BLAKE3 (primary), SHA-2/3 where protocol pins | Address checksum = BLAKE3 |
| KDF (wallet) | Argon2id + XChaCha20Poly1305 | POSIx 0600/0700 enforced |
| VRF | no live VRF: sortition uses the parent-hash draw (`STELL_SORTITION_V5`). Beacon/CN-VRF gates are compiled off (`u64::MAX`); there is no `STELL_VRF_ACTIVATION_HEIGHT` env switch |

## Key/signature sizes (pinned)

- Ed25519 identity key: 32-B pubkey (voter id only).
- Falcon-512: 897-B pubkey, 666-B signature (FIPS 206 parameter set in use).
- Legacy `G=0` keys load without address change (migration invariant).

## Signing standards

- Wallet messages: `STELL-MSGSIG-V1`, chain-id bound (replay across chains fails).
- Consensus votes: chain-id **+ shard-id** + height/round bound preimage under
  `STELLEREUM_BFT_VOTE_V3` (`consensus/types.rs::vote_sign_bytes_for_shard`;
  v1/v2 bytes are refused). See spec 04.
- `STELL-MSGSIG-V1` envelopes also carry paymaster sponsor fields.

## zkML (verifiable inference by re-execution — NOT succinct ZK)

- Protocol tag `STELLEREUM_PQ_STARK_BLAKE3_V1` (`zkml_attestation.rs`) is a
  **legacy committed name**: despite `PQ_STARK_BLAKE3` it is NOT a STARK and
  NOT a SNARK. The verifier **re-executes** the quantized forward pass and
  recomputes the BLAKE3 Merkle trace root + Fiat–Shamir hash. Groth16/arkworks
  were removed (no ark dependency); legacy `snark_*` helper names remain.
- `zkml_capabilities()`: sound, NOT zero-knowledge, NOT succinct, NOT hiding;
  TEST-ONLY deterministic setups are refused a VK on the live path.
  Re-registering the byte-identical model under an existing id is an
  idempotent no-op; different weights under a taken id revert (first writer
  wins).
- ML-DSA-44 (`0x03`): fail-closed DISABLED — `from_id(3)` errs, verify
  returns false, registry refuses (pinned by `mldsa_*` tests).
- Phase-1 tracks live in `stellereum/docs/PLAN-VRF.md` (VRF: math bound, NOT wired into
  sortition); `stellereum/docs/PLAN-POP.md` is retained only as design history —
  its BLS module was deleted, so there is no PoP path to gate.

## Invariants (executable: `cargo test -p stellereum --lib post_quantum`)

1. FIPS-206 test vectors pass; non-FIPS Falcon code paths are absent.
2. Batch verify accepts exactly what single verify accepts (no malleability gap).
3. Legacy keys verify under the same addresses as upgraded keys.
