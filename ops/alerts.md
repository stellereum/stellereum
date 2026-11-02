# Stellereum alert runbook

Companion to `ops/alert_rules.yaml` (Prometheus rules). Every metric below
was verified to exist in `stellereum/src/metrics.rs` on 2026-11-02
(`rg -c '"<name>"' stellereum/src/metrics.rs` returns 1 for each name).

Scrape surface: explorer/gateway on `STELL_EXPLORER_LISTEN`
(default `127.0.0.1:8080`; local-cluster uses `127.0.0.1:18080+i`):
`GET /metrics`, `GET /health`, `GET /healthz`, `GET /api/version`.
JSON-RPC on `STELL_RPC_LISTEN` (default `127.0.0.1:8545`; local-cluster
`127.0.0.1:18645+i`). Local-cluster helpers: `./scripts/local-cluster.sh
status|stop <i>|start <i>|restart <i>`, per-node `live.log` (grep
`FINALIZED block #`), per-node `env.<i>` / `node.yaml` / `node.pid`.

## FinalsStalled

**Signal:** `delta(stell_consensus_height[10m]) <= 0` for 5m.
Finalized height is the chain's liveness heartbeat; no growth means no
finality (rounds may still turn — that is motion without progress).

**Triage:**
1. `curl -s localhost:<exp>/metrics | grep -E 'stell_consensus_(height|round)'`
   — height frozen + round climbing = stuck vote; both frozen = dead loop.
2. `tail live.log | grep -E 'FINALIZED|nil|timeout'` on the node dir.
3. `increase(stell_nil_rounds_total[10m])` — if >= 3, treat as NilRoundsStall.
4. Cross-check peers: `eth_blockNumber` on two other nodes. All frozen =
   network-wide halt (halt procedure, not a single-node restart).
5. Single node frozen while peers advance: `./scripts/local-cluster.sh restart <i>`
   (single-node restart is safe; never restart the whole cluster without a
   human order).

## RoundExplosion

**Signal:** `max_over_time(stell_consensus_round[5m]) > 10`.
Rounds reset to 0 on every new height, so a *sustained* high round means the
height is not turning over: proposer misses, slow validation, or a QC that
never forms.

**Triage:**
1. `stell_proposer_missed_total`, `stell_slow_validation_total` counters —
   which one is moving identifies miss vs slowness.
2. `stell_straggler_grace_extends_total` rate — grace engaging (expected
   liveness signal) vs silent stall.
3. Check CPU/disk on the host before touching the node.

## NilRoundsStall

**Signal:** `increase(stell_nil_rounds_total[10m]) >= 3`. Consecutive nil
rounds stall finality; the breaker fires at K=3 (`stell_nil_breaker_fires_total`).

**Triage:** same as FinalsStalled, plus confirm the breaker fired
(`NilBreakerFired` alert). If nil rounds persist past the breaker, escalate:
likely proposer/partition issue, not load.

## QCFailures

**Signal:** `increase(stell_weak_qc_refused_total[15m]) > 0`.
The unilateral/weak-finalization firewall refused a QC carrying less power
than the quorum of the set in force at its height. Any increase is
actionable: it means someone (or some bug) tried to finalize without quorum.

**Triage:**
1. Correlate with `stell_validator_set_size` / `stell_validator_quorum_power` —
   did the set just change (epoch turn) making old QCs stale?
2. Check peer logs for the refused certificate's height/round.
3. A sustained rate (not a single blip at an epoch boundary) = stop and
   investigate before it becomes a fork. Do NOT "fix" by lowering quorum —
   quorum values are frozen core (AGENTS.md §7).

## MempoolSaturated

**Signal:** `stell_mempool_size > 1600` (warn, ~80% of
`MAX_GLOBAL_BUFFERED_TXS = 2048` in `stellereum/src/mempool.rs`),
`> 1900` (critical).

**Triage:**
1. Split: `stell_mempool_sealed` vs `stell_mempool_plain` — sealed-heavy
   backlog points at unseal/packing, plain-heavy at fee/admission pressure.
2. `stell_mev_unseal_failed_total` moving = unseal path failing, not demand.
3. If blocks are finalizing but the pool still grows, the workload exceeds
   packing; shed client-side (rate-limit submitters), do not raise the cap
   without a spec note (frozen-core-adjacent).

## DiskAbove80Pct

**Signal:** `stell_data_dir_bytes > 0.8 × volume` (default rule value =
0.8 × 100 GiB; set to your volume). Companion `DiskGrowthFast` fires when
`predict_linear(stell_data_dir_bytes[1h], 6h)` crosses the volume size.

**Triage:**
1. `stell_snapshot_count` / `stell_state_entries` — snapshot retention vs
   genuine growth.
2. `scripts/node-prune-cron.sh` is the repo's prune path — run the documented
   prune, then re-verify with `scripts/backup_verify.sh` before deleting
   anything. Never delete live store data without a verified snapshot.
3. If `stell_persist_queue_dropped_total` is also moving, the disk is slow as
   well as full — grow/replace the volume, do not just prune.

## PeersLost

**Signal:** `count(count by (peer) (stell_peer_latency_seconds)) < 3` for 10m.
Derived from the per-peer label set of the SELF-MEASURED latency series
(there is no dedicated peer-count gauge in `metrics.rs`).

**Caveats (read before paging someone):**
- Stale series linger: a dead peer still counts until its series goes stale,
  so this alert UNDER-counts departures. A drop here is real; absence of a
  drop is not proof of health.
- Peer ids are attacker-chosen and label-sanitized; a churn of ids with a
  stable count = rotation, not loss.

**Triage:** compare against P2P dial logs and `stell_peer_round_lag{peer}`
(lag exploding on survivors = network, not membership).

## Downtime-evidence spike

Bucket for integrity counters where ANY increase is evidence. All monotonic,
never reset — alert on `increase(...) > 0`:

| Counter | Meaning |
|---|---|
| `stell_fork_total` | block conflicting with our finalized chain |
| `stell_divergence_total` | proposal refused over post-state-root mismatch |
| `stell_nil_breaker_fires_total` | nil-storm convergence action taken |
| `stell_persist_queue_dropped_total` | disk too slow, persist jobs shed |
| `stell_slow_validation_total` | proposal validation past backpressure threshold |
| `stell_unbound_refused_total` | chain-binding gate refusals (before published activation height = early arming; after = blocked replays) |
| `stell_bls_pop_rejected_total` | bad BLS registry entries skipped |

**Triage:** fork/divergence = stop, preserve logs + data dir (snapshot with
`scripts/backup_verify.sh`), do not restart into the same state blindly.
Persist/slow-validation = host resources first. Unbound-refused = check
against the published activation height before concluding anything.
