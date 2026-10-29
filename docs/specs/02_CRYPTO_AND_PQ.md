# 02 — Crypto & Post-Quantum (HDAE canonical, 2026-10-29)

Source of truth in code: `stellereum/src/post_quantum.rs`, `bls.rs`,
`wallet_signing.rs`, `stellereum/Cargo.toml`.

## Algorithm set

| Use | Algorithm | Notes |
|---|---|---|
| Validator/consensus signatures | Ed25519 (`ed25519-dalek` v2, batch verify) | QC path uses batch verification |
| Post-quantum signatures | Falcon (FIPS 206, via `pqcrypto-falcon`, PQClean C archive) | All 4 live validators hold full PQ key sets |
| Aggregate certificates | BLS12-381 (`bls12_381` v0.9, minimal-pubkey-size: 48-B keys, 96-B sigs) | **No proof-of-possession** — structural gap, tracked |
| Key exchange (mail/overlay) | X25519 + ChaCha20Poly1305 | infnode/infmail |
| Hashing | BLAKE3 (primary), SHA-2/3 where protocol pins | Address checksum = BLAKE3 |
| KDF (wallet) | Argon2id + XChaCha20Poly1305 | POSIx 0600/0700 enforced |
| VRF | planned (`vrf.rs` stub surface, PLAN-VRF) | NOT live — do not claim otherwise |

## Key/signature sizes (pinned)

- Ed25519: 32-B pubkey, 64-B signature.
- Falcon-512: 897-B pubkey, 666-B signature (FIPS 206 parameter set in use).
- BLS12-381: 48-B pubkey, 96-B signature.
- Legacy `G=0` keys load without address change (migration invariant).

## Signing standards

- Wallet messages: `STELL-MSGSIG-V1`, chain-id bound (replay across chains fails).
- Consensus votes: chain-id + height/round bound preimages (see spec 04).
- `STELL-MSGSIG-V1` envelopes also carry paymaster sponsor fields.

## Invariants (executable: `cargo test -p stellereum --lib post_quantum`)

1. FIPS-206 test vectors pass; non-FIPS Falcon code paths are absent.
2. Batch verify accepts exactly what single verify accepts (no malleability gap).
3. Legacy keys verify under the same addresses as upgraded keys.
