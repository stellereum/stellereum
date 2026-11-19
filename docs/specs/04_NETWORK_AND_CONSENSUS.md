# 04 — Network & Consensus (HDAE canonical, 2026-10-29)

> **Ruleset status:** this page is updated for **ruleset v5** (`CONSENSUS_RULESET_VERSION = 5`,
> `DOMAIN_SET_VERSION = 3`, `FORK_ID = 0x9d59096b`, 23 fork-id rules). The v5 change is the
> chain-wide supply cap; v2–v4 are the height re-scale, shard-bound vote preimage, and signed
> block round + timestamp bound. See `docs/RULESET_V2.md`..`docs/RULESET_V5.md` and
> `docs/SUPPLY_CAP.md`. Values below that predate v5 are marked where they are historical.

Source of truth: `stellereum/src/consensus/` (`engine.rs`, `types.rs`,
`sortition.rs`), `runtime/consensus_step.rs`, `node/consensus_driver.rs`,
`consensus_net.rs`, `network.rs`, `sync.rs`, `mempool.rs`, `staking.rs`,
`protocol.rs`.

## BFT core (V5)

- N=4 live, quorum = `floor(2·power/3)+1` over voting power (4/4 set,
  non-fragile; equal to 2f+1 at N=4).
- Leader selection: V5 sortition bound to **parent hash** (verified property).
  The VRF/beacon draws (`BEACON_DRAW_ACTIVATION_HEIGHT`,
  `CNVRF_V3_ACTIVATION_HEIGHT`) are compiled gates that are still `u64::MAX`
  (off); there is **no** `STELL_VRF_ACTIVATION_HEIGHT` env switch on the node.
- QC model: µQC with `MICRO_COMMITTEE_MAX_SIZE = 128` seats
  (`min(N, 128)`); QCs strictly per-round single-quorum.
- Tick floor `STELL_MIN_BLOCK_MS` (default 50 ms,
  `node/policy.rs::DEFAULT_MIN_BLOCK_MS`), base round timeout
  `FROZEN_ROUND_TIMEOUT_BASE_MS = 3_000` ms, r0 fast path; nil path at
  2×timeout.
- Lock rule + `adopt_committed` (H+1 activation for uniformity) + atomic commit
  with undo (non-atomic commit caused fork #288000 — never regress).
- `DIVERGENCE their_root=… our_root=…` journal tag = the fork alarm; the
  watchdog pages on it (pattern `DIVERGENCE|their_root.*our_root`).

## Block identity and layout (ruleset v4/v5)

Canonical hash preimage (`Block::compute_hash`, `sharding/block.rs`); every
bracketed section is **conditional** and zero/empty-skipped so legacy bodies
keep their historical hashes:

```text
STELLEREUM_BLOCK_V3 ‖ chain_id(8,BE) ‖ shard_id(4,BE) ‖ height(8,BE)
  ‖ ["ROUND001"(8) ‖ round(4,BE)]              only when round != 0
  ‖ prev_hash(32) ‖ state_root(32) ‖ tx-count ‖ tx hashes
  ‖ ["ORDROOT1" ‖ order_merkle_root(32)]       only when non-zero
  ‖ xshard-count ‖ msg ids ‖ [full xshard commitments]  only when non-empty
  ‖ ["SHARDHDR" ‖ count ‖ heads]               only when non-empty
  ‖ [epoch-key] ‖ [last QC] ‖ [MMR epoch root] ‖ [CN-VRF v3 payload]
  ‖ timestamp(8,BE) ‖ proposer(32)
```

- **Signed round (v4):** `Block.round` is mixed in under `ROUND001` whenever it
  is non-zero, so the proposer signature and every vote/QC commit to it.
  Validators require `block.round <= hc.round` on admission/validation (an
  earlier signed round is the lock-rescue/late-frame path; a FUTURE round is
  refused) and require `block.round <= certificate.round` on adopt. Round 0
  hashes exactly as a pre-v4 body; there is no second encoding.
  **Not a liveness fix:** the live round-divergence defect (same body voted at
  different rounds) is still open — see `docs/LIVENESS_ROUND_SYNC_AUDIT.md`.
- **Chain-wide supply (v5):** each `ShardHeaderCommitment` carries cumulative
  `minted_total_nano` (genesis included), domain-separated by `SHMINT01` and
  zero-skipped inside `commitment_bytes`. The masterchain block hash covers the
  head set, the quorum signs it, and the masterchain aggregates the heads and
  refuses any head/aggregate above `TOTAL_SUPPLY_CAP` or a shard's static
  `SupplyPartition` share. See `docs/SUPPLY_CAP.md`.
- `Block`'s trailing fields are append-only with `serde(default)` + legacy
  local-store tolerance (the WIRE path stays strict). Current tail order:
  `precommit_qc`, `shard_headers`, `order_merkle_root`,
  `epoch_key_commitment`, `last_qc`, `mmr_epoch_root`, `cnvrf_v3`, and
  **`round` (last field)**. Any new field goes last with a zero/`None` default,
  else old nodes fork.

## Deterministic block timestamp (ruleset v4)

`runtime::consensus_step::check_block_timestamp` gates the proposal AND adopt
paths with a pure function of the two headers (no wall-clock read):

```text
height > 0:  parent.timestamp <= block.timestamp
             <= parent.timestamp + MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1_000
```

`MAX_BLOCK_TIMESTAMP_DRIFT_MS = 3_600_000` (1 hour; block timestamps are
seconds). Height 0/genesis is exempt; the first block after the zero-genesis
anchor is exempt from the FORWARD bound only (the anchor has no timestamp),
while monotonicity still holds. An unknown parent timestamp fails closed. The
honest proposer clamps into the same window (`MAX_TIMESTAMP_JUMP_SECS = 3_600`).

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

- Chain-wide native supply cap: `TOTAL_SUPPLY_CAP = 1e9 STELL` (nano units),
  partitioned across the committed shard set and enforced again by the
  masterchain over committed shard heads (ruleset v5). **Not** one cap per
  engine — see `docs/SUPPLY_CAP.md`.
- Staking floors enforced (999/1470/1999/2000 tiers seen live); F1 reward
  accumulator; vote-equivocation slash path exists (5%).
- Proposal-equivocation slashing is **ACTIVE** from genesis under v4
  (`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT = 0`): the evidence rule is same
  shard + height + **signed round** + differing block hashes, with both
  proposer signatures verified. A same-body pair and an honest cross-round
  re-proposal are not evidence.
- Replay protection rollout (legacy unbound envelopes) is pending — track as
  open item, do not mark complete.
