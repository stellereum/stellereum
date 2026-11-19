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

- Shard routing by tx prefix; workchain shard-1 currently PARKED on the live
  chain (empty, no user txs — unpark needs funded demo + serving RPC). The
  `{0,1}` pair is supported without the experimental hatch.
- Cross-shard value uses the §9 2PC (PREPARE → PREPARE-ACK → COMMIT) from
  genesis: `XPC_ACTIVATION_HEIGHT = 0` is compiled into the chain spec;
  `STELL_XPC_ACTIVATION_HEIGHT` is deprecated and ignored. The target credits
  only a COMMIT proven against the source's committed state, and counts that
  credit in the same `cross-shard inbound credited N` apply log/counter as a
  legacy inbound. The cross-shard mailbox prunes every consumed record by
  `msg_id` on apply (idempotent, node-local KV hygiene; not consensus state).
  See `docs/TWO_SHARD_DEPLOY.md` and `scripts/soak_two_shard.sh`.
- Catch-up is event-driven: a verified `Committed`/`Proposal`/`Vote` (or a
  peer head pointer) above our tip schedules the attempt on the next tick,
  with a 500 ms reactive floor. The periodic timer is a backstop only:
  `STELL_CATCHUP_INTERVAL_MS` defaults to **30 s**, and a node at the tip
  skips the DHT probe entirely. One pass is bounded by
  `STELL_CATCHUP_BUDGET_MS` (default **250 ms**). Snapshot fetch + `stelops`
  checkpoint verify (gap-0 rule), lockclear on anchor-trap, and hourly prune
  timers are unchanged.
- Validator mesh: `ValidatorMesh` (network.rs) is installed from the pinned
  validator peers and keeps persistent direct links warm (10 s heartbeat,
  reconnect after cooldown, rotation-aware membership). Its eviction policy
  is **3 consecutive direct failures → 60 s cooldown**
  (`VALIDATOR_MESH_EVICT_AFTER`, `VALIDATOR_MESH_COOLDOWN_MS`). The infnode
  transport applies the same suspicion policy under
  `INFNODE_PEER_EVICT_COOLDOWN_MS` (default `60_000`). **Current wire path:**
  consensus delivery still uses the pubsub/DHT broadcast path — the mesh's
  `deliver_consensus_mesh` is not yet called by the consensus sender. The DHT
  is discovery + blob storage only; it never decides consensus validity.
- Compact gossip is active from genesis (`COMPACT_GOSSIP_ACTIVATION_HEIGHT =
  0`): the proposal path ships header + 6-byte short ids, bounded
  `BodyPull`/`Body` (64 ids, 3 attempts, 32 MiB frame), and a full body only
  for misses/sealed txs. See `docs/COMPACT_PROPAGATION.md`.
- P2P: QUIC + pubsub topic `stellereum/consensus/v1/<chain-id>/shard/1`;
  stream caps shed slow peers (receiver-side drops are expected under load).

## Economics safety

- Staking floors enforced (999/1470/1999/2000 tiers seen live); F1 reward
  accumulator; equivocation slash path exists.
- Replay protection rollout (legacy unbound envelopes) is pending — track as
  open item, do not mark complete.
