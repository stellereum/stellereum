# stellereum-ledger-tool

`stellereum-ledger-tool` is a small **offline** verifier for Stellereum block
files. It does not open a node store, does not connect to a node, and does not
need a running chain.

The crate is standalone: it has its own empty `[workspace]` table. It uses the
`stellereum` crate only for the block type and hash function; its other
dependencies are `bincode` and `hex`.

> Scope: it verifies current-format block bytes and hash-linked segments. It is
> **not** a consensus verifier. It does not check signatures, QCs, finality,
> state roots, execution, or authenticity, and it cannot tell a genuinely
> finalised chain from a well-formed fabricated one. See
> [“What it does not do”](#what-it-does-not-do).

## What it reads and writes

| Item | Behaviour |
| --- | --- |
| Input | One or more **current-v1 block files** produced by the node's `bincode` fixed-integer encoding (`Storage::put_block`). |
| Output | Human-readable text on stdout; errors on stderr. |
| Writes | **None.** It never creates, modifies or deletes a file. |
| Store access | **None.** `inspect-block`, `verify-block` and `verify-chain` refuse a directory and only read regular files. `repair` and `export` always refuse. |
| Network | **None.** |
| Input bounds | 32 MiB per block, at most 1024 blocks per `verify-chain` invocation. Decoded heap and hash computation are **not** covered by that limit. |

Input must be a **stable, independent copy**. The tool does not take a
snapshot, lock the source, or detect concurrent changes. Do not point it at a
live store while the node is running, and do not point it at a file another
process is still writing.

## Build

```sh
cargo build --release --manifest-path stellereum-ledger-tool/Cargo.toml
# binary: stellereum-ledger-tool/target/release/stellereum-ledger-tool
```

## Commands

All commands are implemented in `src/main.rs`.

### `inspect-block`

```sh
stellereum-ledger-tool inspect-block <bincode-file> <chain-id>
```

Decodes one block, prints its height, shard, chain id and computed block hash.
It is inspection only; no expected hash is compared.

### `verify-block`

```sh
stellereum-ledger-tool verify-block <bincode-file> <chain-id> <expected-hash-hex>
```

Same decode and inspection, then compares the computed hash with
`<expected-hash-hex>`. The expected value must be exactly 64 hex characters
(32 bytes) and match `Block::compute_hash()` for this block.

### `verify-chain`

```sh
stellereum-ledger-tool verify-chain current-v1 <chain-id> <block-file> [block-file...]
```

Accepts only the format name `current-v1`. For each supplied file it:

1. decodes a canonical current-format block (no legacy tolerance, no trailing
   bytes);
2. checks that heights are consecutive;
3. checks that every block is on the same shard;
4. checks that each block's `prev_hash` equals the **computed** hash of the
   preceding block;
5. prints the ending height, shard, chain id and computed tip hash;
6. prints exactly what it did **not** check.

The files must be supplied in ascending height order. Reversed, gapped,
mixed-shard and mismatched-parent inputs fail. A chain longer than 1024 blocks
is refused.

### `repair` and `export`

```sh
stellereum-ledger-tool repair [arguments...]
stellereum-ledger-tool export [arguments...]
```

Both commands **always refuse**:

```text
refused: no safe repair/export implementation; requires an offline,
consistent independent copy, validated recovery procedure, and an explicitly
authorized destination; this tool never opens a store
```

This is intentional. There is no in-tree block export path; supplying block
files is the operator's or a separate tool's responsibility.

## Chain id

`<chain-id>` must be a nonzero unsigned integer. Zero is refused because the
node substitutes its configured default for zero, which would make the check
ambiguous. The tool sets the process-local `STELL_CHAIN_ID` to the supplied
value before calling `Block::compute_hash()` so the chain-bound hash matches
the node's.

For the public testnet the value is **5757** (the node's default chain id). If
you are verifying a copy from another network, use that network's id.

## Examples

```sh
BIN=stellereum-ledger-tool/target/release/stellereum-ledger-tool

# Inspect one independently obtained block file.
$BIN inspect-block /tmp/opencode/block-00420000.bin 5757

# Compare it with a hash recorded elsewhere.
$BIN verify-block /tmp/opencode/block-00420000.bin 5757 \
  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Check a contiguous segment (three files, ascending height).
$BIN verify-chain current-v1 5757 \
  /tmp/opencode/blocks/00419998.bin \
  /tmp/opencode/blocks/00419999.bin \
  /tmp/opencode/blocks/00420000.bin
```

Expected shape:

```text
height: 420000
shard: 0
chain id: 5757
computed block hash: <64 hex>
inspection only: no expected hash supplied
scope: computed block hash and optional comparison only, not byte-for-byte integrity; no QC, finality, signatures, state, store integrity, or chain validation
input must be an independent stable file; concurrent changes are not detected
input limit: 32 MiB; decoded heap and hash computation are not bounded by this limit
```

For `verify-chain` the last lines are:

```text
consistent unanchored segment: 3 blocks, ending height 420000, shard 0, chain id 5757
computed tip hash: <64 hex>
checked: current-v1 canonical encoding, consecutive heights, same shard, and parent links to computed block hashes
not checked: trusted anchor, authenticity, signatures, QC, state, finality, consensus validity, or byte-for-byte integrity; a fabricated chain can pass
input must be independent stable files; concurrent changes are not detected
input limit: 32 MiB per block, 1024 blocks; decoded heap and hash computation are not bounded by this limit
```

Exit code is `0` on success and `1` on any refusal, decode error or mismatch.

## Safety

* **Never run it against a live store.** The tool will refuse a directory, but
  the correct procedure is still: stop the node or take a filesystem snapshot,
  copy the block files to an independent location, and verify the copy.
* **A live file can change under the reader.** There is no lock and no
  snapshot; a torn read is possible if the source is still being written.
  Copy first, verify the copy.
* **Do not treat a pass as consensus approval.** `verify-chain` proves
  structural continuity of the supplied bytes, not that a validator set signed
  them or that the chain is final.
* **Bound untrusted input at the OS level.** The 32 MiB limit bounds the input
  byte count, not the decoded allocation or hash work; use `ulimit -v`/cgroups
  when verifying files from an untrusted source.

## What it does not do

The tool prints this scope on every run. In short:

* no signature, validator-set or QC verification;
* no finality, state-root, execution or consensus-validity check;
* no trusted anchor (it verifies **un**anchored segments only);
* no byte-for-byte file integrity claim — `compute_hash()` does not cover
  every encoded field (signatures are not part of it);
* no legacy block formats;
* no store repair, export or migration.

For chain health, use `scripts/cluster_liveness.sh`; for fork comparison of
stopped nodes, use `stelops diverge`; for consensus validity, the node itself
is the authority.

## Tests

The crate has 9 unit tests in `src/main.rs` and 2 CLI integration tests in
`tests/cli.rs` (11/11 total, recorded in `docs/OPEN_DEFECTS.md`, W2-LEDGER-TOOL):
canonical round-trip, truncation/trailing-byte refusal, forged collection
length, hash mismatch, exact 32-byte hex parsing, size limits,
unsafe-command refusal, and chain-link/shard/order checks.

```sh
cargo test --manifest-path stellereum-ledger-tool/Cargo.toml
```
