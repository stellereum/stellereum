# 04 — Network & Consensus (HDAE canonical, 2026-10-29)

Source of truth: `stellereum/src/consensus.rs`, `runtime.rs`, `main.rs`,
`consensus_net.rs`, `network.rs`, `sync.rs`, `mempool.rs`, `staking.rs`.

## BFT core (V5)

- N=4 live, quorum = 2f+1 over voting power (4/4 set, non-fragile).
- Leader selection: V5 sortition bound to **parent hash** (verified property).
  VRF-gated rule (default off): at/after `STELL_VRF_ACTIVATION_HEIGHT` with a
  verified proof, the seed is the VRF election output; otherwise (and for all
  pre-activation history, which verifies forever) it stays parent-hash.
- QC model: µQC with k=64 micro-quorums; QCs strictly per-round single-quorum.
- Tick 50ms (`TICK_MS`), base timeout 3500ms, r0 fast path; nil path at 2×timeout.
- Lock rule + `adopt_committed` (H+1 activation for uniformity) + atomic commit
  with undo (non-atomic commit caused fork #288000 — never regress).
- `DIVERGENCE their_root=… our_root=…` journal tag = the fork alarm; the
  watchdog pages on it (pattern `DIVERGENCE|their_root.*our_root`).

## Block anatomy (frozen field order — last-field rule)

`order_merkle_root`, `shard_headers`, `epoch_key_commitment`, `last_qc`,
`mmr_epoch_root` (**last field, zero-unless-proven**). Any new field goes last
with a zero default, else old nodes fork.

## Timing/liveness stack (do not remove — each fixed a measured stall)

- Proposer prebuild + vote-fan-in pipeline (VEL): mean 1744→635ms in harness.
- Verify-once caches (STAB): validate p99 18.35→9.93ms.
- 50ms floor tick (R1–R4), adaptive timeout + nil-breaker K=3 (C2).
- Measured live (2026-10-28): sustained ~2–3 s/block, p50 bursts ~0.5 s.
  Residual to 0.5 s sustained = WAN RTT floor + 1-vCPU members (physics, not bugs).

## Sharding & sync

- Shard routing by tx prefix; workchain shard-1 currently PARKED (empty, no
  user txs — unpark needs funded demo + serving RPC).
- Catch-up: snapshot fetch from tip node + `stelops` checkpoint verify
  (gap-0 rule), lockclear on anchor-trap, prune timers hourly on all nodes.
- P2P: QUIC + pubsub topic `stellereum/consensus/v1/<chain-id>/shard/1`;
  stream caps shed slow peers (receiver-side drops are expected under load).

## Economics safety

- Staking floors enforced (999/1470/1999/2000 tiers seen live); F1 reward
  accumulator; equivocation slash path exists.
- Replay protection rollout (legacy unbound envelopes) is pending — track as
  open item, do not mark complete.
