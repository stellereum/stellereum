# Stellereum alert runbook

Companion to `ops/alert_rules.yaml` (Prometheus rules). Every `stell_*`
metric below was verified to exist in `stellereum/src/metrics.rs` on
2026-11-02 (`rg -c '"<name>"' stellereum/src/metrics.rs` returns 1 for each
name), **except** the `stell_cluster_*` liveness gauges and the
`stell_tick_*` / `stell_clock_*` health gauges: those are written by
`scripts/cluster_liveness_watch.sh` through the node_exporter textfile
collector (see ClusterLivenessFailed below).

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

## ClusterLivenessFailed / ClusterHeightSpread

**Signal:** `stell_cluster_liveness_ok == 0` for 2m, or
`stell_cluster_spread > 1` for 2m.

These series do **not** come from the node's `/metrics`. They are produced by
`scripts/cluster_liveness_watch.sh`, which runs the read-only
`scripts/cluster_liveness.sh` every 60 s and atomically rewrites
`stell_cluster_liveness.prom` for the node_exporter **textfile collector**:

```bash
scripts/cluster_liveness_watch.sh \
  --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" \
  --min-reachable 2 \
  --journal "A=ssh root@hostA journalctl -u stell-nodeA" \
  --journal "B=journalctl --user -u stell-nodeB" \
  --clock "A=ssh root@hostA 'timedatectl show -p NTPSynchronized --value; date +%s%3N'" \
  --clock "B=timedatectl show -p NTPSynchronized --value; date +%s%3N" \
  --log /var/log/stell/cluster-liveness.log \
  --textfile /var/lib/node_exporter/textfile_collector/stell_cluster_liveness.prom
```

Metrics: `stell_cluster_liveness_ok`, `stell_cluster_height`,
`stell_cluster_spread`, `stell_cluster_stalled_seconds`, plus the per-node
tick/clock series described under TickP99High and ClockSkew.

**Caveats:**
- `--min-reachable N` is forwarded to the probe: it requires N configured RPC
  endpoints to return valid heights in the **final poll** (N must be a positive
  integer no greater than the endpoint count). Below N gives `STALLED` / exit 1,
  unless observed divergence takes precedence. The default is effectively 1,
  so `OK` can include down endpoints; inspect `reachable=N/M` in the log.
  Choose N for the monitoring policy (2 requires both endpoints above).
  RPC reachability is neither P2P connectivity nor validator voting power or
  quorum; verify those independently.
- `OK` means the reachable tip was not classified as stalled, not that every
  endpoint advanced or was reachable. A short window cannot prove progress.
- A stopped watcher leaves the last value in the textfile; it can look healthy
  forever. Alert on node_exporter `up` separately (see `ops/status_page.md`).
- `spread` is max−min height, so it catches a lagging node; it does not catch a
  same-height fork on its own. `cluster_liveness.sh` also compares block hashes
  at the lowest final-poll height when it is > 0 and at least two endpoints
  are reachable; differing returned hashes give `DIVERGED`. Failed or missing
  hash lookups do not fail `OK`, so `OK` does not prove hash agreement.
- A 2m `for:` on `liveness_ok` means transient single-poll stalls are filtered;
  the script's own window is 60 s by default.

**Triage:**
1. Run the same command without the wrapper:
   `scripts/cluster_liveness.sh --rpcs "..." --min-reachable N --journal "<per-node journal cmd>"`.
   Use the same N as the watcher and `--window 90`.
2. Height split (spread > 1): note which node is behind and by how much.
   Check whether it is advancing (compare `height` deltas, not one sample).
   Do not wipe. Restart only the lagging node when it is not catching up;
   see `docs/TESTNET_READINESS_OPS.md` §9.
3. Round split (equal/near heights, `/health` shows rounds far apart and no
   finality): capture `round` / `last_finalized_round` from every node before
   touching anything. This is the failure mode documented in
   `docs/LIVENESS_ROUND_SYNC_AUDIT.md`; a coordinated restart may be needed.
4. Confirm the genesis/fork identity before any destructive action:
   `/health` `.identity.chain_id` / `.identity.fork_id` must match across
   nodes and the expected values. **Do not wipe data unless the genesis/fork
   id changed.**

## TickP99High

**Signal:** `stell_tick_p99_ms > 2000` for 10m, per `node` label.

The watcher parses `[perf] tick h=... took ...` lines from each node's journal
over a bounded window (`--tick-window`, default 900 s) and exports
`stell_tick_p50_ms`, `stell_tick_p99_ms`, `stell_tick_over_1s_ratio` and
`stell_tick_samples`. **The node logs a tick line only when the tick takes
>=400 ms** (`consensus_driver.rs`), so these are statistics of slow ticks, not
of every tick. Zero `stell_tick_samples` means the journal command returned
nothing — check the `--journal` command before believing a 0 p99.

**Why it matters:** apply+flush runs inside the tick. A multi-second tick
defers proposals (`proposal deferred: apply in flight`) and shows up as
multi-second block-time gaps. The public site samples block time from block
timestamps, so a tick spike corrupts that number too.

**Triage:**
1. Read the raw lines:
   `journalctl -u stell-nodeA --since=-15min | grep '\[perf\] tick' | tail -20`
   The line names the cause: `flushes=N` (more outbox batches inside one
   tick), `catchup_ms`, `retro_ms`, `probe_ms`, `join_ms`.
2. Check host CPU/IO. A build or test run on the validator is the usual
   culprit on a 1-vCPU host; confirm with `ps`, load average, and
   `journalctl` for the compile window.
3. Correlate with `proposal deferred: apply in flight` and block gaps in the
   same journal. Slow disk also shows as `stell_persist_queue_dropped_total`
   (see Downtime-evidence spike).
4. Do not restart a healthy node for a transient spike. Remove the load, let
   the 10m window clear, and confirm p99 and the ratio fall.

## TickSlowRatioHigh

**Signal:** `stell_tick_over_1s_ratio > 0.2` for 10m, per `node` label.

This is the breadth signal: more than 20% of *logged* ticks exceed 1000 ms.
Because only ticks >=400 ms are logged, the ratio describes the slow-tick
sample, not the full tick stream. A high ratio with a moderate p99 means
sustained load; a high p99 with a low ratio means rare multi-second outliers
(apply/retro/join). Use both with `stell_tick_samples`.

**Triage:** same as TickP99High. If the ratio is high while p99 is near 1 s,
look for a constant CPU/IO consumer (a build, a compaction/sweeper, a noisy
neighbour); if p99 is several seconds, look for apply or catch-up work inside
the tick.

## ClockSkew

**Signal:** `stell_clock_sync_ok == 0` for 5m, per `node` label.

`stell_clock_skew_ms{node}` is node epoch-milliseconds minus the watcher's
midpoint clock for the same command round-trip (positive = node ahead;
`NaN` when the `--clock` command prints no timestamp). `stell_clock_sync_ok`
is 0 when `|skew| > 1000 ms`, when `timedatectl` reports
`NTPSynchronized=no`, or when the clock status is unknown. The default
`--clock` command measures the watcher's local host, so supply a per-node
`--clock` (usually over ssh, as in the example above) for remote validators.

**Why it matters:** block timestamps come from each node's clock. A node with
NTP disabled and a +13.4 s offset produced negative block-timestamp intervals
and fake 12 s gaps, which the public block-time display then showed as real.

**Triage:**
1. On the affected host: `timedatectl set-ntp true` (or enable chrony /
   systemd-timesyncd), then `timedatectl timesync-status`.
2. Confirm `NTPSynchronized=yes` and an offset well under 1 s. Re-check the
   textfile: `stell_clock_skew_ms` within ±1000 ms and
   `stell_clock_sync_ok{node="X"} 1`.
3. Confirm the chain agrees: sample consecutive block timestamps at the same
   heights from two nodes and check there are no negative deltas:
   ```bash
   for h in 12340 12341 12342 12343 12344; do
     curl -s -H 'content-type: application/json' \
       --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_getBlock\",\"params\":[{\"height\":$h}]}" \
       http://127.0.0.1:8545 | jq -r '.result.timestamp'
   done | awk 'NR>1 && $1 < prev { print "NEGATIVE delta", prev, "->", $1 } { prev=$1 }'
   ```
   Repeat against the second node at the same heights. Both nodes must agree
   and every delta must be non-negative.
4. Do not step a running validator's clock backwards without a named
   maintenance window; a forward step is the safe direction if a correction
   is unavoidable.

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

## Live 4-validator cluster (ops/observability)

The rules in this file are the **registry-only reference**. The canonical rules
for the live A/B/C/D cluster are `ops/observability/alerts.yml` (Prometheus +
Alertmanager + Grafana stack in `ops/observability/`). Thresholds differ on
purpose (node_exporter percentages, 4-validator quorum, participation), so do
not load both into the same Prometheus and do not copy thresholds between them.

New alerts and their runbooks (anchors in `ops/observability/README.md`):

| Alert | Signal | Severity |
| --- | --- | --- |
| `ValidatorQuorumLow` | `stell_validator_set_size < 4` or `stell_validator_set_fragile == 1` | critical |
| `ValidatorJailed` | `stell_validator_efficiency_ratio[15m]` max = 0 | critical |
| `ValidatorNotVoting` | 15m mean of `stell_validator_efficiency_ratio` < 0.9 | warning |
| `NodeOutOfSync` | height > 50 below cluster max for 2m | warning |
| `BlockStall` | `delta(stell_consensus_height[60s]) <= 0` | critical |
| `DiskUsageHigh` / `DiskWillFillIn24h` | node_exporter filesystem > 80% / 24h projection | warning / critical |
| `InodesHigh` | node_exporter inodes > 80% | warning |
| `ApplySlow` / `CpuPerBlockHigh` | p95 apply > 50ms / CPU per block > 400ms | warning |
| `PersistQueueBacklog` | `stell_persist_queue_depth > 100` for 5m | warning |
| `DivergenceDetected` / `ForkDetected` | any `increase(...[5m]) > 0` | critical |
| `FalconSignRate` | signing rate 0 while `stell_ready == 1` | info |

`FinalsStalled` maps to `BlockStall` + `NodeOutOfSync`; `ForkSpike` /
`DivergenceSpike` map to `ForkDetected` / `DivergenceDetected`. Nothing is
contradictory: this file keeps its historical thresholds for a single-target
lab, the cluster file owns the live 4-validator thresholds. Triage steps for
the new names are in `ops/observability/README.md#alert-catalogue`.
