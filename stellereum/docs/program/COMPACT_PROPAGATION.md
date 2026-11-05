# Compact Block / Vote Propagation — perf design (NO wire change)

Status: **design + KAT prototype only**. Prototype lives in
`stellereum/src/compact_prop.rs`, which is **unwired** (no `mod` line;
`grep -rn compact_prop stellereum/src` hits only that file) and compiles
standalone with `rustc --test`. Per `AGENTS.md` §7 (frozen core: wire
format), nothing here ships without a spec update + audit note + full gate.

## 1. Current wire sizes (measured, bincode 1.3.3)

Method: offline harness (`/tmp`, repo untouched) replicating the exact field
order/types of `TransactionWire` (stellereum/src/sharding.rs:2356-2369),
`Vote`/`VoteKind` (consensus.rs:1531-1546), `QuorumCertificate`
(consensus.rs:2805-2812), `ConsensusMsg` (consensus_net.rs:270-305), `Block`
(sharding.rs:4890-5070), encoded with bincode 1.3.3 (stellereum/Cargo.toml:20):

| Object | Bytes |
|---|---|
| tx plain (Ed25519 64 B sig, empty payload) | 176 |
| tx priority-bid envelope (80 B sig) | 192 |
| vote bare, `Some(hash)` / nil | 153 / 121 |
| vote Falcon hybrid envelope (746 B sig = 16 magic + 64 Ed + 666 Falcon) | 835 |
| `ConsensusMsg::Vote`, locked=None (classical baseline) / locked=Some | 158 / 190 |
| vote Falcon hybrid anatomy: 8+4+4+33+32+(8+746) = 835 (sig field 746 = `VOTE_FALCON_PART_LEN`, consensus.rs:214) | — |
| QC(k Ed25519, refused under pure PQ) = 57 + 104·k (k=1:161, 4:473, 7:785, 10:1097, 100:10457) | — |
| µQC Falcon envelope = 73 + ceil(C/8) + s·670 (s sigs; 670 = 4 len + 666 Falcon) | — |
| block fixed part (0 txs, 1 proposer sig, no QCs) | 350 |
| `Proposal(N)` = 366 + 176·N (N=0:366, 1:542, 100:17966, 428:75694, 1000:176366) | — |
| `Committed{100 txs, qc7}` (classical baseline) | 18747 |
| µQC Falcon envelope C=4 full-sign: 73 + 1 + 4·670 = 2754 (QC bincode 97 + 2754 = 2851) | — |

Encoding (confirmed by harness): fieldless enum = u32 (4 B), `Option` tag =
1 B, `Vec` len = u64 (8 B). E.g. vote = 8+4+4+33+32+(8+64) = 153. ✓

Gossip paths (read-only): `ConsensusMsg::{Proposal,Vote}` fire-and-forget
gossip under `MAX_BATCH_ITEMS=32` / `MAX_BATCH_BYTES=512 KiB` /
`MAX_CONSENSUS_MSG=32 MiB` (consensus_net.rs:71-88); full bodies also travel
via DHT blob + KV hash with `fetch_block` by hash (network.rs:541-590) —
the precedent for body-pull. Existing compact-ish mechanisms (no change):
gossip `Batch` amortization, proposer exact-size trim (runtime.rs:4430-4449),
`estimate_tx_wire_bytes` packing (mempool.rs:2614), µQC `signers_bitmask`
(consensus.rs:1203), thin-proposal outbox dedup (main.rs:1320-1335).

## 2. Design

**Tx short-ids.** Compact proposal carries `Vec<[u8;6]>` instead of full
txs; `short_id = HASH(salt || txid)[..6]`, `salt` = `prev_hash` (no extra
bytes, kills cross-height precomputation). Non-mempool txs (sealed MEV
envelopes, etc.) always travel full. Receiver resolves via local mempool
index; miss/ambiguity → bounded `BodyPull`. Fail-closed: block hash is still
over full txs.

**QC bitfield (PQ-live).** Live verification checks the Falcon µQC envelope
(`QC_UQC_MAGIC` 16 B + `sortition_parent` 32 B + scheme 1 B + height 8 B +
round 4 B + committee 4 B + bitmask-len 4 B + bitmask + sig-count 4 B +
s·(4 + 666) sigs; layout consensus.rs:825-836, formula pinned by
`pq_qc_sizes_vs_classical`) or the CEC epoch envelope (`QC_PQ_MAGIC`);
standalone classical/BLS legs are refused under pure PQ. The canonical
bitfield (sorted-`ValidatorId` order, trailing bits zero-or-reject) travels
inside the µQC envelope as `signers_bitmask`: attribution/evidence reuse it
without re-walking sig lists. No aggregate swap is defined — there is no BLS
path to activate.

**Header-first + body-pull sketch.** 1) gossip
`CompactProposal{header, short_ids}`; 2) resolve locally, pull missing
(capped requests, 3 attempts); 3) only fully-resolved bodies enter prevote;
4) `Committed` keeps the full block + QC (rare catch-up path).

## 3. Projected savings

`CompactProposal(N, misses m) = 366 + 6·N + 176·m`:

| N | baseline | compact m=0 | compact m=5% |
|---|---|---|---|
| 100 | 17966 | 966 (−94.6%) | 1846 (−89.7%) |
| 428 | 75694 | 2934 (−96.1%) | 6700 (−91.1%) |
| 1000 | 176366 | 6366 (−96.4%) | 15166 (−91.4%) |

QC bitfield: already inside the µQC envelope (no extra overhead). PQ
`ConsensusMsg::Vote` wire size: UNVERIFIED — needs a harness re-measure with
the 746 B hybrid sig field (the 158 B row above is the refused classical
baseline). Votes otherwise untouched by this design.

## 4. Risks

- **Mempool-sync assumption:** savings assume receivers hold the txs; a
  byzantine proposer inflates misses → pull amplification. Mitigations: id
  caps, attempt bounds, peer down-scoring, `MAX_CONSENSUS_MSG` still caps
  every frame.
- **Short-id DoS:** 48-bit birthday @1000 txs ≈ 9e-10/block; targeted hit
  needs 2^48 trials; near-miss spam pollutes indexes. Mitigations:
  per-height salt, collision ⇒ miss (pull full, never mis-execute), admission
  fees make grinding cost real, O(1) bounded lookups.
- **No wire change yet:** needs spec + audit per §7; this doc is input to
  that process.

## 5. Validation

- KAT: `rustc --test --edition 2021 stellereum/src/compact_prop.rs -D
  warnings` → **4 passed, 0 failed** (short-id vectors cross-checked against
  an independent Python FNV-1a reference; bitfield pack/unpack incl.
  fail-closed trailing-bit cases; size math vs §1 measurements).
- Because the file is unwired it cannot run under `cargo test`; the lead
  wires a test-only `mod` later if this design is accepted.
