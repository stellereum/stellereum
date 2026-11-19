# Compact Block / Vote Propagation — wired proposal path, compact µQC codec

Status: **INSTALLED and ACTIVE from genesis** (`COMPACT_GOSSIP_ACTIVATION_HEIGHT = 0`).
The compact **proposal** path is wired end to end on the live node: sender
selector, receiver state machine, bounded body server, and a loopback that
re-enters the ordinary full-`Proposal` drain. The compact **µQC** codec is also
implemented and gated (`encode_compact_qc_gossip` / `decode_compact_qc_gossip`,
`compact_gossip_bytes_for` / `parse_compact_qc_incoming`), but its
broadcast/admit call sites in `node/consensus_driver.rs` are still deferred, so
finality continues to gossip the full `Committed` envelope. (`ConsensusMsg::decode`
does not parse the magic-prefixed µQC frame; that frame has its own decoder.)

Code: `stellereum/src/compact_prop.rs` (included by
`consensus_net.rs` via `#[path = "compact_prop.rs"] pub mod compact_prop`) and
the wiring in `stellereum/src/consensus_net.rs` +
`stellereum/src/node/consensus_driver.rs`. Pins:
`stellereum/tests/compact_gossip_tests.rs`, `consensus_net` unit tests.

Per `AGENTS.md` §7 this is frozen-core surface: the wire variants and their
bounds are append-only, and changing them needs a spec update + audit note.

## 1. Wire sizes (measured, bincode 1.3.3)

Method: offline harness (`/tmp`, repo untouched) replicating the exact field
order/types of `TransactionWire` (`stellereum/src/sharding.rs:2356-2369`),
`Vote`/`VoteKind` (`consensus.rs:1531-1546`), `QuorumCertificate`
(`consensus.rs:2805-2812`), `ConsensusMsg` (`consensus_net.rs`), `Block`
(`sharding.rs:4890-5070`), encoded with bincode 1.3.3
(`stellereum/Cargo.toml:20`):

| Object | Bytes |
|---|---|
| tx plain (Ed25519 64 B sig, empty payload) | 176 |
| tx priority-bid envelope (80 B sig) | 192 |
| vote bare, `Some(hash)` / nil | 153 / 121 |
| vote BLS envelope (176 B sig, flag-off nodes never emit) | 265 |
| vote Falcon envelope (746 B sig) | 835 |
| `ConsensusMsg::Vote`, locked=None (live path) / locked=Some | 158 / 190 |
| QC(k Ed25519) = 57 + 104·k (k=1:161, 4:473, 7:785, 10:1097, 100:10457) | — |
| block fixed part (0 txs, 1 proposer sig, no QCs) | 350 |
| `Proposal(N)` = 366 + 176·N (N=0:366, 1:542, 100:17966, 428:75694, 1000:176366) | — |
| `Committed{100 txs, qc7}` | 18747 |
| BLS QC envelope fixed header + bitfield ceil(C/8) (C=7:1, 10:2, 100:13, 1000:125) | 161 + … |

Encoding (confirmed by harness): fieldless enum = u32 (4 B), `Option` tag =
1 B, `Vec` len = u64 (8 B). E.g. vote = 8+4+4+33+32+(8+64) = 153. ✓

Gossip paths: `ConsensusMsg::{Proposal,Vote}` fire-and-forget gossip under
`MAX_BATCH_ITEMS=32` / `MAX_BATCH_BYTES=512 KiB` / `MAX_CONSENSUS_MSG=32 MiB`;
full bodies also travel via DHT blob + KV hash with `fetch_block` by hash —
the precedent for body-pull. Existing compact-ish mechanisms (no change):
gossip `Batch` amortization, proposer exact-size trim, `estimate_tx_wire_bytes`
packing, µQC `signers_bitmask`, thin-proposal outbox dedup.

## 2. Proposal path (wired)

**Tx short-ids.** A compact proposal carries `Vec<[u8;6]>` instead of full
txs; `short_id = BLAKE3("STELL_COMPACT_SHORT_ID_V1" || salt || txid)[..6]`,
`salt = BLAKE3("STELL_COMPACT_SALT_V1" || height_le || prev_hash)` (derived
from the announced header, so it costs no wire bytes). Non-mempool txs
(sealed MEV envelopes, private bodies) travel full in `full_txs`,
index-anchored so body order is preserved. A collision resolves to a **miss**,
never a guess. Fail-closed: the announced `block_hash` is the hash of the FULL
block; the receiver rebuilds the body in announced slot order, checks the
order commitment and refuses a body that does not hash to it. A short id never
authorises execution.

**Sender.** `proposal_gossip_msg(block, round)` returns
`ConsensusMsg::CompactProposal` when the block compresses, otherwise the plain
`ConsensusMsg::Proposal`. `propose()` calls it and
`CompactBodyServer::remember(block, round)` before enqueueing, so announced
blocks can answer bounded pulls. The full body still goes to the DHT/sync
catch-up path.

**Receiver.** `CompactReceiver` opens via `open_compact_proposal` (gate +
structural bounds), builds `ShortIdIndex` from `Mempool::all()`, and resolves.
Outcomes are concrete (`CompactInbound`):
- `Ready { round, block }` — every slot resolved and the hash matched; the node
  re-encodes it as a wire `Proposal` and pushes it back into the bounded
  deferred queue, so the ONE existing proposal path performs attribution, H+1
  deferral, hints, `on_proposal` and the vote. There is no second consensus
  path.
- `Pull(pull)` — missing slots within budget; one bounded `BodyPull` is
  broadcast.
- `FetchFull` — misses exceed the pull budget, or attempts are exhausted; the
  node falls back to the plain full-proposal fetch (a far-ahead height also
  seeds catch-up evidence). It never prevotes on a partial body.
- `Refused` — counted and dropped loudly.

**Body server.** `CompactBodyServer::serve` answers a `BodyPull` only for a
block this node recently announced and only when every requested tx is BOTH in
the announced block AND still in the local mempool. It never serves from
arbitrary storage, never fabricates, and returns silence (`Ok(None)`) when it
cannot answer.

**Bounds (all fail-closed):**

| Bound | Value | Meaning |
|---|---|---|
| `COMPACT_GOSSIP_ACTIVATION_HEIGHT` | `0` | active from genesis; `u64::MAX` height is still refused |
| `COMPACT_MAX_IDS` | 10,000 | slots one proposal may name |
| `COMPACT_MAX_FULL_SLOTS` | 1,024 | inline bodies one proposal may carry |
| `COMPACT_PULL_MAX_IDS` | 64 | ids per `BodyPull` |
| `COMPACT_PULL_MAX_ATTEMPTS` | 3 | pull attempts before full-proposal fallback |
| `COMPACT_MAX_BYTES` | 32 MiB | hard ceiling for proposal/pull/body frames (= `MAX_CONSENSUS_MSG`) |
| `COMPACT_MAX_PARKED` | 4 | parked resolutions in one receiver |
| `COMPACT_PARKED_BYTES` | 64 MiB | byte budget for parked resolutions |
| `COMPACT_SERVED_BLOCKS` | 2 | recently announced blocks retained for pulls |
| `COMPACT_SERVED_BYTES` | 64 MiB | byte budget for the served-block cache |

Eviction is oldest-first within both the count and byte budgets. A single
over-budget proposal is still parked alone (refusing a legal 32 MiB frame
would make it unresolvable).

## 3. Compact µQC codec

The live finality frame carries the full bincode `QuorumCertificate` (outer
framing plus one 32-byte `ValidatorId` per signer). `STCMQC01`-prefixed
frames carry the SAME certificate content bitfield-indexed instead: no
per-signer ids, no outer struct framing. `encode_compact_qc_gossip` extracts
the µQC envelope, `decode_compact_qc_gossip` rebuilds the identical live QC,
and verification stays the unmodified `QuorumCertificate::verify`.

Bounds: committee ≤ 4096, per-signature ≤ 2048 B, frame ≤ 32 MiB, canonical
bitfield (exact length, trailing bits zero), exactly one signature per set
bit, no trailing bytes. A 64-seat full-sign Falcon-512 frame measures 42,987
B; a 43-of-64 quorum frame 28,917 B.

Status: **codec live, emitter/admit hookup deferred.** `compact_gossip_bytes_for`
and `parse_compact_qc_incoming` are implemented and gated, but no node call
site currently replaces the full `Committed` send or consumes a compact frame
on receipt. Old software ignores the magic and fails its bincode-only decode
closed, so the frame is forward-compatible.

## 4. Projected savings

`CompactProposal(N, misses m) = 366 + 6·N + 176·m`:

| N | baseline | compact m=0 | compact m=5% |
|---|---|---|---|
| 100 | 17966 | 966 (−94.6%) | 1846 (−89.7%) |
| 428 | 75694 | 2934 (−96.1%) | 6700 (−91.1%) |
| 1000 | 176366 | 6366 (−96.4%) | 15166 (−91.4%) |

QC hybrid (BLS-off): +ceil(C/8)+1 B overhead now (C=100: +14 B). Votes
untouched (158 B live path).

## 5. Risks

- **Mempool-sync assumption:** savings assume receivers hold the txs; a
  byzantine proposer inflates misses → pull amplification. Mitigations: id
  caps, attempt bounds, peer down-scoring, `MAX_CONSENSUS_MSG` still caps
  every frame, and the receiver's parked count/byte budgets.
- **Short-id DoS:** 48-bit birthday @1000 txs ≈ 9e-10/block; targeted hit
  needs 2^48 trials; near-miss spam pollutes indexes. Mitigations:
  per-height salt, collision ⇒ miss (pull full, never mis-execute), admission
  fees make grinding cost real, O(1) bounded lookups.
- **Wire change:** the three variants are APPENDED after `Batch`, so every
  pre-existing variant keeps its tag. `ConsensusMsg::decode` refuses the
  `u64::MAX` sentinel and every structurally invalid frame; a non-zero gate can
  be installed for a coordinated upgrade without touching the codec.
- **Not yet compact:** the µQC emitter/admit hookup is deferred, so finality
  bandwidth is unchanged until that lands.

## 6. Validation

- `cargo test -p stellereum --test compact_gossip_tests` drives the REAL
  emitter, wire codec and receiver: full-mempool round-trip (zero pulls),
  partial-mempool pull, cold-mempool fallback, hash-mismatch refusal,
  oversized/duplicate/mismatched body refusal, collision ⇒ miss, 400-tx
  savings measurement, and the below-gate refusal via
  `with_compact_gossip_gate`.
- `compact_prop` unit tests pin the short-id KAT (BLAKE3 domain), bitfield
  pack/unpack fail-closed cases, size math vs §1, and compact-QC
  round-trip/tamper refusal.
