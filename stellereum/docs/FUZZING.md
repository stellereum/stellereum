# Fuzzing the decoders

Stellereum's remote attack surface starts at decoders: bytes chosen by a peer,
or JSON chosen by an unauthenticated RPC client, are parsed before any
authentication, quorum check, or state transition. The C1 consensus review
found two remote-abort bugs (nested `Batch` recursion and an unbounded
proposer-signature scan) by reading code. This harness exists so the next
decoder bug is found by a fuzzer, not by luck.

The harness is a standard `cargo-fuzz` package at `fuzz/` and is intentionally
not part of the normal `cargo test` or pull-request CI: it needs nightly and
minutes of CPU. See `.github/workflows/fuzz.yml`.

## Ground rules

1. **A decoder crash is a P0.** A panic on peer bytes is a remote denial of
   service. Fix the decoder and add the crashing input to
   `fuzz/corpus/<target>/` as a permanent regression before closing the issue.
2. **Never weaken the assertion to make the fuzzer pass.** If an invariant
   (`never trusted`, `never verifies`, `never nests`) fails, the decoder is
   wrong until proven otherwise.
3. **Never point a target at a live node, store, or key.** Every harness is
   pure, in-process, and takes `&[u8]`; no target opens a socket or a database.
4. **Cap the input.** Each target returns early above 1 MiB. That keeps one
   iteration cheap and prevents a fuzzer from spending its budget mutating
   quarter-gigabyte hex envelopes. Production caps remain in the decoders.

## Targets and exact entry points

All paths below are reachable through the public crate root
(`stellereum::...`); the harness package depends on the node as an ordinary
path dependency.

| Target | Entry point(s) | Input | Invariant beyond "no panic" |
|---|---|---|---|
| `frame_decode` | infnode transport frame decoder | raw frame | none |
| `consensus_msg_decode` | `consensus_net::ConsensusMsg::decode`, `consensus_net::parse_incoming`, `consensus_net::parse_incoming_with_peer_key`, `consensus_net::parse_tx_incoming` | raw bincode, or UTF-8 JSON `{topic,data[,src]}` | a decoded batch is `<= MAX_BATCH_ITEMS` and never contains another `Batch` (the C1-F2 fix) |
| `transaction_decode` | `sharding::Transaction` bincode | raw bincode | none |
| `block_decode` | `sharding::Block` bincode | raw bincode | none |
| `cert_envelope_decode` | `consensus::decode_pq_micro_envelope`, `consensus::decode_pq_epoch_envelope`, `sharding::PqSignatureEnvelope::decode`, `post_quantum::PqSignatureEnvelope::decode` | raw envelope bytes | a decoded certificate round-trips through its canonical encoder |
| `evm_raw_tx_decode` | hand-rolled EVM RLP decoder | raw RLP | none |
| `peer_msg_decode` | `network::P2pNetworkAdapter::parse_cross_shard_incoming`, `mev_epoch::MevFrame::decode`, `mev_epoch::decode_sealed_payload` | raw frame | a remote cross-shard message is never `trusted`; frames re-encode byte-identically |
| `vote_qc_decode` | `consensus::Vote` and `consensus::QuorumCertificate` bincode | raw bincode | a QC never verifies against an empty committee; empty signature bytes never verify even with every signer id given power |
| `rpc_json_decode` | `serde_json` body parse + `serde_json::from_value::<rpc::RpcRequest>` (the path used by `rpc::streams::rpc_handler` and `ws_handle_text`) | UTF-8 JSON, single or batch | none; malformed request must not abort |
| `falcon_sig_decode` | `consensus::verify_falcon_signature` (public alias of `post_quantum::verify_pq_signature` with `Falcon512`) | exactly 666-byte signature frames | an arbitrary frame never verifies against a fixed deterministic key |

### Entry points that are not public

`post_quantum::unpack_falcon_sig` is private. `falcon_sig_decode` therefore
uses the nearest public entry point, `consensus::verify_falcon_signature`,
which unpacks the same 666-byte frame (header `0x29`, 40-byte nonce,
`comp_encode`d `s2`, zero padding) before the lattice check. The harness
generates one deterministic verification key at startup with
`FalconKeypair::generate_from_seed_bytes`; the single-byte
`generate_from_seed` helper is `cfg(any(test, debug_assertions))`, so an
optimized fuzz build must not rely on it.

JSON-RPC **dispatch** (`RpcState`, `dispatch`, async method handlers) is out of
scope: it needs a live node and wall-clock state. The fuzzer covers the
parser every request reaches first.

## Run locally

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd stellereum
cargo +nightly fuzz run consensus_msg_decode -- -max_total_time=60
```

Replay the committed corpus (no mutation, useful as a fast regression gate):

```sh
cargo +nightly fuzz run vote_qc_decode -- -runs=0
```

Run every target for a minute, mirroring CI:

```sh
for t in frame_decode consensus_msg_decode transaction_decode block_decode \
         cert_envelope_decode evm_raw_tx_decode peer_msg_decode \
         vote_qc_decode rpc_json_decode falcon_sig_decode; do
  cargo +nightly fuzz run "$t" -- -max_total_time=60 -timeout=25
done
```

Do not set `RUSTFLAGS`. cargo-fuzz picks the sanitizer (`-Zsanitizer=address`)
and the matching flags; exporting `RUSTFLAGS` replaces that set and silently
turns sanitizer coverage off.

`tests/fuzz_decoder_tests.rs` replays a subset of the legacy targets under a
stable `cargo test`; the Wave 4 targets (`vote_qc_decode`,
`rpc_json_decode`, `falcon_sig_decode`) are libFuzzer-only by design.

## Seeds and corpus

Seed files are ordinary bytes under `fuzz/corpus/<target>/`:

* `vote_qc_decode/` — fixint bincode: `height u64`, `round u32`, `kind u32`,
  `Option<[u8;32]>`, `[u8;32]` voter, `u64` length-prefixed signature, `u32`
  shard id. A QC replaces the voter+signature with a `u64` count of
  `(id, length-prefixed signature)` pairs.
* `rpc_json_decode/` — a single call, a notification, a batch, and a
  wrong-type body.
* `falcon_sig_decode/` — 666-byte frames: zeros, canonical `0x29`, rejected
  reference header `0x39`, and `0xFF`.
* `consensus_msg_decode/` — JSON envelopes. The node repository's
  `.gitignore` ignores this directory under its existing generated-corpus
  policy, so its seeds are local. Regenerate one with any
  `ConsensusMsg::encode()` output, hex-encode it, and wrap it as
  `{"topic":"stell/consensus/0","data":"<hex>"}`.

libFuzzer writes newly discovered inputs into the corpus directory as it runs
(it mutates the corpus in place). Keep interesting ones; delete only noise you
can explain. Crash reproducers land in `fuzz/artifacts/<target>/` and are never
committed there.

## Reading a crash

A crash produces a message like:

```
==12345== ERROR: AddressSanitizer: stack-overflow on address ...
SUMMARY: AddressSanitizer: stack-overflow ...
artifact_prefix='./artifacts/consensus_msg_decode/'; Test unit written to ./artifacts/consensus_msg_decode/crash-<hash>
```

1. Reproduce the exact input:

   ```sh
   cargo +nightly fuzz run consensus_msg_decode fuzz/artifacts/consensus_msg_decode/crash-<hash>
   ```

   Add `RUST_BACKTRACE=1` for a Rust backtrace (ASan/UBSan reports are printed
   first and are the authoritative failure).

2. Identify the decoder frame with `cargo fuzz fmt`:

   ```sh
   cargo +nightly fuzz fmt vote_qc_decode fuzz/artifacts/vote_qc_decode/crash-<hash>
   ```

3. Minimise while preserving the crash: `cargo +nightly fuzz tmin <target>
   <artifact>`. Keep both the minimised input and the original if they fail
   differently.

4. Fix the decoder in `src/`. A fix that only catches the current byte pattern
   is not a fix; the invariant (bounds check, length cap, non-recursive parse,
   fail-closed verify) must hold for the whole class.

5. **Add the reproducer to the corpus** under its target and commit it:

   ```sh
   cp fuzz/artifacts/vote_qc_decode/crash-<hash> \
      fuzz/corpus/vote_qc_decode/regression-<short-description>
   ```

6. Re-run the corpus in CI (`-runs=0`) and the nightly workflow. The
   regression is permanent: it must never be deleted to make a run green.

If the failure is a timeout or OOM rather than a panic, treat it the same way:
an input that makes one peer frame consume unbounded CPU or memory is a remote
DoS. A deliberate `-timeout`/`-rss_limit_mb` increase needs a written reason
and a decoder-side cap, not just a CI flag.

## CI

`.github/workflows/fuzz.yml` runs nightly and on `workflow_dispatch` only
(never on pull requests). It builds every target with `cargo fuzz build`, then
runs each for `-max_total_time=60` (overridable in the dispatch form). One
crash fails the job and uploads `fuzz/artifacts/**`. The existing `ci.yml`
smoke job builds the harness and replays a small number of runs on pull
requests; it is a compile/regression check, not a substitute for the nightly
run.

## Initial verified run (2026-11-25)

All 10 targets ran sequentially under `cargo +nightly fuzz run` with
`-rss_limit_mb=3072`, `taskset -c 8-11 nice -n 19`: **23,550,124 total
executions, 0 crashes, 0 panics, 0 OOMs**.

| Target | Duration | Executed units | Avg exec/s | Peak RSS (MiB) | Result |
| --- | --- | --- | --- | --- | --- |
| `consensus_msg_decode` | 61s | 707,605 | 11,600 | 126 | 0 crashes |
| `block_decode` | 21s | 144,160 | 6,864 | 94 | 0 crashes |
| `cert_envelope_decode` | 21s | 8,242,876 | 392,517 | 559 | 0 crashes |
| `evm_raw_tx_decode` | 21s | 2,367,585 | 112,742 | 471 | 0 crashes |
| `falcon_sig_decode` | 21s | 938,658 | 44,698 | 605 | 0 crashes |
| `frame_decode` | 21s | 8,540,334 | 406,682 | 486 | 0 crashes |
| `peer_msg_decode` | 21s | 179,811 | 8,562 | 97 | 0 crashes |
| `rpc_json_decode` | 21s | 1,996,878 | 95,089 | 531 | 0 crashes |
| `transaction_decode` | 21s | 217,166 | 10,341 | 95 | 0 crashes |
| `vote_qc_decode` | 21s | 215,051 | 10,240 | 94 | 0 crashes |

