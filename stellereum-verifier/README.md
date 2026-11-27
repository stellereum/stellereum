# `stellereum-verifier`

Independent, clean-room, zero-node-dependency post-quantum (PQ) verifier for Stellereum L1 (Ruleset v7).

`stellereum-verifier` depends only on minimal cryptographic and serialization primitives (`bincode`, `blake3`, `hex`, `serde`, `sha2`, `sha3`, and `std`). It has **no dependency on the `stellereum` node crate** (which appears only under `[dev-dependencies]` for differential parity tests), reads no environment variables, and makes no network or RPC calls. Every verification parameter is supplied explicitly.

## Verification Scope

- **Strict v7 canonical wire decoding** (`wire`): exact bincode-1.3 fixint decoding with canonical re-encode parity checks, bounded block/envelope sizes, and canonical `shard_headers` ordering.
- **NIST FIPS 206 Falcon-512** (`falcon512`): pure-Rust Falcon-512 signature verification (`0x29` header) and PQ address derivation (refusing legacy classical schemes and disabled schemes such as ML-DSA-44).
- **Block & header commitments** (`block_hash`): two-level `BlockHeader` v4 (`STELLEREUM_HDR_V4\0`) and `body_commitment` (`STELLEREUM_BODY_V4\0`) with v3 fallback (`STELLEREUM_BLOCK_V3`), `order_merkle_root`, cross-shard `msg_id` / commitment checks, and deterministic timestamp drift bounds.
- **Consensus & sortition** (`consensus`): exact `u128` quorum math, height-indexed PQ key history, proposer signatures, `QuorumCertificate` verification (µQC, CEC, C1 split, `last_qc` binding), and BLAKE3 / CN-VRF v3 sortition.
- **Transactions** (`tx`): `PQ1` explicit/implicit envelopes, `SF1` session-key delegation, `SP1` Paymaster v2 sponsorship, `PRIORITY` fee tags, and `chain_id` binding.
- **State commitments** (`commitment`): `cpat2` Merkle inclusion/exclusion proofs and 17-domain `CommitmentSnapshot` v5 SHA-256 framing.

## CLI Subcommands

### 1. `verify-tx`

Verify a single canonical v7 transaction binary (`PQ1` / `SF1` / `SP1`).

```text
stellereum-verifier verify-tx <tx.bin> [--chain-id N] [--require-chain-id]
```

### 2. `verify-block`

Verify a single canonical v7 block binary.

```text
stellereum-verifier verify-block <block.bin> [OPTIONS]
```

### 3. `verify-chain`

Verify a contiguous sequence of blocks (height continuity, `shard_id` continuity against `blocks[0].shard_id`, `prev_hash` linkage, timestamp bounds, and cross-block implicit key registration when `--verify-txs` is enabled).

```text
stellereum-verifier verify-chain <block.bin>... [OPTIONS]
```

#### Block / Chain Flags

| Flag | Description |
| :--- | :--- |
| `--chain-id <N>` | Chain ID bound by signatures and block hashes (default `5757`). |
| `--validators <FILE>` | Out-of-band validator set and PQ key registry (`<hex32-id> <power> [<scheme> <hex-pubkey>]` per line). |
| `--schedule <parent-hash\|beacon>` | Committee sortition schedule (default `parent-hash`). |
| `--qc-split-height <H>` | Activation height for the C1 µQC / full-QC split (`ConsensusConfig`). |
| `--sortition-unbiased-height <H>` | Activation height for unbiased rejection-sampling sortition (`ConsensusConfig`). |
| `--header-commit-height <H>` | Activation height for v4 two-level header commitments (`ConsensusConfig`). |
| `--require-qc` | Refuse a block that carries no precommit `QuorumCertificate` (requires `--validators`). |
| `--require-chain-id` | Refuse transactions that do not bind `chain_id` (requires `--validators`). |
| `--verify-txs` | Verify every transaction in each block (requires `--validators`). |

Without `--validators`, `verify-block` and `verify-chain` perform structural verification only: strict v7 wire decoding, canonical `shard_headers`, `order_merkle_root`, cross-shard `msg_id` and `trusted == false` checks, and (for `verify-chain`) height, `shard_id`, `prev_hash`, and timestamp linkage.

### 4. `verify-snapshot`

Verify a 17-domain `CommitmentSnapshot` v5 digest against a `state_root` (either supplied via `--state-root` or extracted from a canonical v7 `--block` header).

```text
stellereum-verifier verify-snapshot [--state-root <hex32>] [--block <block.bin>]
                                    --snapshot <json> (--proof <json> | --accounts <json>)
```

- `--state-root <hex32>`: 32-byte state root (accepts optional `0x` / `0X` prefix). Optional if `--block` is passed; if both `--state-root` and `--block` are passed, they must match `block.header().state_root`.
- `--block <FILE>`: Canonical v7 block file whose `header.state_root` is bound.
- `--snapshot <FILE>`: JSON object containing `"version": 5`, required domain hex blobs (`tokens`, `staking`, `pmm`, `contracts`, `escrow`, `governance`, `oracle`, `session_keys`, `books`, `bridge`, `cross_shard`, `xpc`), and optional domains (`zkml`, `cnvrf`, `total_minted_nano`, `evm_bindings`, `pq_registry`).
- `--proof <FILE>`: JSON array of canonical `cpat2` proof nodes proving inclusion of `commitment_key() -> snapshot.digest()` at `state_root`.
- `--accounts <FILE>`: JSON array of `{"key":"<hex32>","value":"<hex>"}` covering every non-commitment trie leaf; rebuilds the full `cpat2` root and verifies equality with `state_root`.

### 5. `verify-proof`

Verify a standalone `cpat2` inclusion or exclusion proof against a `state_root`.

```text
stellereum-verifier verify-proof --state-root <hex32> --key <hex32>
                                 (--value <hex> | --absent) --proof <json>
```

- `--value <hex>`: Expected leaf value bytes for an inclusion proof (accepts optional `0x` / `0X` prefix).
- `--absent`: Verify an exclusion proof showing `key` is absent at `state_root`.
- `--proof <FILE>`: JSON array of canonical `cpat2` proof nodes.

All CLI hex arguments and JSON hex fields accept both `0x` and `0X` prefixes. The built-in strict RFC 8259 JSON parser rejects duplicate keys, unknown fields, trailing bytes, and nesting deeper than `MAX_JSON_DEPTH = 64`.

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | **Verified** — all cryptographic, consensus, structural, and commitment checks passed. |
| `1` | **Verification refused** — strict wire decode failure, signature/quorum/sortition/linkage rejection, `state_root` mismatch against `--block`, or `cpat2` / snapshot commitment verification failure. |
| `2` | **Usage, IO, or parse error** — invalid/missing CLI flags, unreadable files, invalid hex or validator-file syntax, or malformed/excessively nested (`> 64`) JSON. |

## Trust Boundaries

- **Validator set & PQ key history (`--validators`)**: The verifier has no access to on-chain staking state and trusts the caller-supplied validator file as the root of trust for proposer, vote, and QC key lookups.
- **Beacon schedule (`--schedule beacon`)**: In CLI mode without an out-of-band `EpochBeacon`, `CommitteeSchedule::Beacon(None)` is passed and any consensus check requiring a beacon committee or proposer draw fails closed.
- **Snapshot preimages (`--snapshot`)**: `verify-snapshot` independently verifies the consensus-critical v5 framing (`COMMITMENT_VERSION = 5`), domain ordering, conditional empty-domain encoding, and SHA-256 commitment digest, and binds that digest to `state_root`. However, the per-domain preimage byte blobs are supplied by the caller; to avoid trusting a node for domain serialization, the caller must recompute those preimages from its own state engine.
- **Proof vs. full trie rebuild**: `verify-snapshot --proof` proves only that the snapshot commitment leaf folds into `state_root`; `verify-snapshot --accounts` additionally verifies the entire `cpat2` trie leaf set against `state_root`.
