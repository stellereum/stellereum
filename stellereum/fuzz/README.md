# Fuzz harnesses

`cargo-fuzz` / libFuzzer harnesses for every decoder that consumes bytes a
remote peer or an unauthenticated RPC client chooses. The operating guide
(reading crashes, triage, corpus policy) is [`../docs/FUZZING.md`](../docs/FUZZING.md).

## Layout

```
fuzz/
  Cargo.toml            # separate package: stellereum-fuzz
  fuzz_targets/*.rs     # one [[bin]] per target, all libFuzzer
  corpus/<target>/      # committed seed inputs + promoted regressions
```

The harness package depends on the node as an ordinary path dependency
(`stellereum = { path = ".." }`) and on the sibling `infnode` checkout at
`../../infnode/crates/infnode`. `libfuzzer-sys` is behind the default
`libfuzzer` feature so `cargo fuzz run` links the harness (see the comments in
`Cargo.toml`).

Every target catches a panic only to re-raise it as `abort()`: libFuzzer only
records a crash on a signal, so a swallowed unwind would hide exactly the bug
the harness is looking for.

## Targets

| Target | Decoder | Assertion beyond "no panic" |
|---|---|---|
| `frame_decode` | infnode transport frame | none (decoder shape only) |
| `consensus_msg_decode` | `ConsensusMsg::decode`, `parse_incoming`, `parse_incoming_with_peer_key`, `parse_tx_incoming` | decoded batches respect `MAX_BATCH_ITEMS` and are never nested |
| `transaction_decode` | `sharding::Transaction` bincode | none |
| `block_decode` | `sharding::Block` bincode | none |
| `cert_envelope_decode` | µQC/CEC/PQ signature envelopes | decoded certificates round-trip through their canonical encoder |
| `evm_raw_tx_decode` | hand-rolled EVM RLP transaction decoder | none |
| `peer_msg_decode` | cross-shard message + epoch-seal frames | remote cross-shard messages are never `trusted`; frames re-encode byte-identically |
| `vote_qc_decode` | `Vote` / `QuorumCertificate` bincode | empty/forged signature sets never verify; a QC never verifies against an empty committee |
| `rpc_json_decode` | JSON-RPC body → `rpc::RpcRequest` | none (request parsing must not abort) |
| `falcon_sig_decode` | arbitrary 666-byte Falcon-512 frames → `verify_falcon_signature` | arbitrary frames never verify |

## Run locally

Requires nightly Rust plus `cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd stellereum
cargo +nightly fuzz run consensus_msg_decode -- -max_total_time=60
```

Replay the committed corpus only (fast, deterministic once built):

```sh
cargo +nightly fuzz run vote_qc_decode -- -runs=0
```

Do **not** export `RUSTFLAGS`: cargo-fuzz selects the sanitizer and its flags.
Overriding them silently disables ASan/UBSan coverage.

## Seeds and regressions

Seed files live in `corpus/<target>/`; they are ordinary byte files (JSON
bodies, bincode frames, 666-byte Falcon frames). The current committed seeds
were produced from the wire layouts documented in the decoder source:

* `vote_qc_decode/` — fixint bincode (`height u64`, `round u32`, `kind u32`,
  `Option<[u8;32]>`, `[u8;32]` voter, `u64`-prefixed signature, `u32` shard;
  the QC additionally has a `u64`-prefixed `(id, sig)` vector).
* `rpc_json_decode/` — single call, notification, batch, and wrong-type bodies.
* `falcon_sig_decode/` — exactly 666 bytes: all-zero frame, canonical `0x29`
  header, the rejected reference `0x39` header, and an `0xFF` frame.
* `consensus_msg_decode/` — JSON `{topic,data}` envelopes. The node-repo
  `.gitignore` ignores this directory (existing corpus policy), so these seeds
  are local; regenerate them with any `ConsensusMsg::encode()` output.

**A crash input is a regression test.** Move it from `fuzz/artifacts/<target>/`
into `corpus/<target>/`, fix the decoder, and keep the input. See
`docs/FUZZING.md`.
