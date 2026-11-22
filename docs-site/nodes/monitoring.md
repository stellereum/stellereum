---
title: Monitoring
description: "/metrics, key log lines, liveness watchdogs and alert thresholds that actually catch failures."
outline: deep
---

# Monitoring

Monitoring answers three separate questions: whether the chain is advancing, whether nodes agree on state, and whether the host or network is failing. This page maps the probes, metrics and log lines to the alerts that catch real outages.

There are **three** signal sources, and none of them alone is enough:

| Source | What it answers | Where |
| --- | --- | --- |
| Node gateway | is the chain advancing and ready? | `/healthz`, `/readyz`, `/metrics` on `STELL_EXPLORER_LISTEN` (default `127.0.0.1:8080`) |
| Node RPC | do nodes agree on state? | `stell_getStateRoot`, `stell_getValidators`, `stell_blockNumber` |
| Host / infnode | is the box or the network sick? | `df -i`, `du`, journald, infnode `metrics-listen` |

::: tip The single most valuable check
Poll `stell_getStateRoot` on **every** node every minute. All nodes must return
the same 64-hex root. This catches a split chain, a divergent state
application, and a node running alone on its own genesis — none of which is
visible in a height gauge.
:::

## Probes

### `/healthz` — liveness

```bash
curl -s http://127.0.0.1:8080/healthz
```

```json
{"status":"ok","service":"stellereum-gateway"}
```

Cheap by design: no locks, no state reads. It answers 200 whenever the process
can answer HTTP, even if consensus is wedged. Use it only to distinguish
"process alive" from "process gone".

### `/readyz` — readiness

```bash
curl -s -w '\nHTTP:%{http_code}\n' http://127.0.0.1:8080/readyz
```

Ready:

```json
{"ready":true,"failed_checks":[],"height":194,"peers":1,
 "secs_since_finalized":2,"max_stall_secs":30,"min_peers":1}
```

Stalled and peerless:

```json
{"ready":false,
 "failed_checks":["no_peers","finality_stalled","height_stalled"],
 "height":194,"peers":0,"secs_since_finalized":187,
 "max_stall_secs":30,"min_peers":1}
```

`failed_checks` values:

| Check | Meaning |
| --- | --- |
| `no_peers` | fewer than `STELL_READY_MIN_PEERS` connections |
| `no_finality` | nothing has ever finalized |
| `finality_stalled` | no finalize for longer than `STELL_READY_MAX_STALL_SECS` |
| `height_zero` | height is still 0 |
| `height_stalled` | height not advancing for longer than the stall window |

Thresholds: `STELL_READY_MAX_STALL_SECS` (default 30),
`STELL_READY_MIN_PEERS` (default 1; set `0` for solo/dev).

`/readyz` returns **503** with the same shape when not ready. Alert on the
status code and on the specific `failed_checks` set.

### `/metrics` — Prometheus

```bash
curl -s http://127.0.0.1:8080/metrics | grep -E '^(stell_|stellereum_)'
```

The exposition combines the consensus registry and gateway gauges. Known
families:

| Metric | Type | Meaning |
| --- | --- | --- |
| `stell_consensus_height` | gauge | height the consensus engine is working on |
| `stell_consensus_round` | gauge | current round at the active height |
| `stell_block_interval_seconds` | histogram | finalized block interval |
| `stell_block_txs` | histogram | transactions per block |
| `stell_consensus_votes_total{kind}` | counter | votes by kind |
| `stell_peer_latency_seconds{peer}` | histogram | peer latency |
| `stell_fork_total` | counter | blocks conflicting with this node's finalized chain |
| `stell_mempool_size` | gauge | pooled transactions |
| `stell_state_root_commits_total` | counter | state-root commit operations |
| `stell_validator_set_size` | gauge | active validator count |
| `stell_unbound_tx_total` | counter | unbound (replayable) transactions admitted |
| `stell_mempool_sealed` / `stell_mempool_plain` | gauge | sealed vs plain pool entries |
| `stell_mev_unsealed_total` / `stell_mev_unseal_failed_total` | counter | sealed-path outcomes |
| `stellereum_block_height` | gauge | finalized height |
| `stellereum_mempool_size` | gauge | pending transactions |
| `stellereum_contracts_total` | gauge | deployed contracts |
| `stellereum_tokens_total` | gauge | fungible tokens |
| `stell_ready` | gauge | 1 = `/readyz` ready, 0 = not |

`stell_consensus_height` and `stellereum_block_height` carry the same height;
`stell_mempool_size` appears in both places.

::: warning A gauge is not a liveness signal
A node frozen at 4,000 and a node producing 2.5 blocks/s both report a
plausible number. Alert on the **derivative** over a few minutes, not the
value.
:::

## Alert thresholds

### Chain liveness

```text
# No finalized block in 2 minutes (adjust to your block tempo)
time() - max_over_time(stellereum_block_height[2m]) == 0
```

Better: compute the rate and require progress:

```text
# Blocks per second, 5-minute window
rate(stellereum_block_height[5m])
```

| Condition | Severity | Meaning |
| --- | --- | --- |
| `rate(stellereum_block_height[5m]) == 0` for 2 min | critical | chain or node stalled |
| rate far below `1 / STELL_MIN_BLOCK_MS` | warning | proposer not selected every height, or slow host |
| `stell_ready == 0` for 1 min | critical | not ready per `/readyz` |
| `stell_fork_total` increases | critical | conflicting blocks observed |
| `stell_consensus_round` climbing without height | warning/critical | view-change storm |
| `stell_validator_set_size` changes unexpectedly | warning | set churn / a node dropped peers |
| `stell_unbound_tx_total` increasing | warning | replayable traffic admitted |

### Quorum and peers

```text
stell_validator_set_size < 4
```

Two- and three-validator networks halt on a single outage. Alert when the set
is below 4, and when reachable power is below quorum.

`stell_getValidators` reports `quorum` and `fragile`. `fragile: true` means
quorum needs 100 % of the set; page on it.

### Mempool

| Reading | Meaning |
| --- | --- |
| 0 and height flat | chain stalled, not busy |
| non-zero and height flat | producer refusing pooled txs (stale nonce, balance) |
| pinned at cap (10,000) | pool full; only a higher-fee funded tx displaces |
| `stellereum_mempool_size` above ~9,000 | degraded; check admission and proposer |

### Disk and inodes (external)

```bash
df -i /root/nodeA/data     # warn ≥ 80 %, critical ≥ 90 %
df -h /root/nodeA/data
du -sh /root/nodeA/data/store
```

| Condition | Severity | Action |
| --- | --- | --- |
| inode use ≥ 80 % | warning | run the sweeper |
| inode use ≥ 90 % | critical | run the sweeper now; a full table is read-only and silently drops consensus |
| store growth faster than disk headroom | warning | switch to prune mode (`STELL_ARCHIVE=0`) |
| `[storage] persist queue full` in stderr | critical | disk too slow; move to SSD |

There is **no disk metric** in `/metrics`; monitor the host.

### Network (infnode)

If `metrics-listen:` is set in `node.yaml`:

```text
infnode_connections_active
infnode_reconnects_total
infnode_messages_published_total
infnode_messages_delivered_total
infnode_frames_in_total / _out_total
infnode_bytes_in_total / _out_total
infnode_outbox_size
infnode_outbox_dropped_total
infnode_peers_configured
infnode_uptime_seconds
```

| Condition | Meaning |
| --- | --- |
| `infnode_connections_active` below configured peers + climbing `infnode_reconnects_total` | earliest signal a validator is unreachable |
| `published` climbing, `delivered` flat | votes leave this node and arrive nowhere |
| `outbox_dropped_total` climbing | local backpressure / slow consumer |

The reconnect loop retries every 20 s; allow one interval before concluding
anything.

## State agreement

Poll per node, every minute:

```bash
for rpc in http://10.0.0.1:8545 http://10.0.0.2:8545 http://10.0.0.3:8545; do
  printf '%s ' "$rpc"
  curl -s -X POST "$rpc" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"stell_getStateRoot","params":{}}'
  echo
done
```

Interpretation:

| Observation | Meaning |
| --- | --- |
| same height, same root | healthy |
| different height, same root | normal catch-up |
| same height, different root | **split / divergent state** — stop transacting |
| different height, different root | compare roots at a **common** height; if still different, split |
| same root, different validator sets | config drift; compare `validators:` and `total_power` |

Pair `stell_getStateRoot` with `stell_blockNumber` and
`stell_getValidators`. A node reporting an empty/zero-power set never enters
consensus.

For a stronger check, verify a finalized header's quorum certificate against an
out-of-band validator set:

```bash
stellereum light-client --from http://127.0.0.1:8545 \
  --verify <address hex> --validators validators.json
```

The server's word is never enough: a made-up root, a certificate signed by
non-validators, and a proof from another chain are all refused.

## Key log lines

Watch stderr explicitly; some lines bypass structured logging.

| Line | Meaning | Action |
| --- | --- | --- |
| `[storage] persist queue full; dropping a job (disk too slow?)` | on-disk state behind memory | disk incident |
| `[storage] persist error: …` | write failure | disk/permissions |
| `[rpc] server error: …` | RPC handler error | investigate |
| `genesis state root mismatch …` | config/binary differs from chain | restore original config; do not wipe blindly |
| `REFUSING to run on unverified state` | snapshot verification failed | restore a verified backup |
| `REFUSING to join consensus on unhealed state` | heal failed after retries | restore/backup |
| `[mempool] admitting UNBOUND …` | replayable transaction accepted | bind wallets; watch counter |
| `[mempool] evicted N unexecutable transaction(s)` | stale nonce/balance in pool | normal under churn; investigate if constant |
| `[upgrade] UPGRADE TRIGGERED at height …` | plan reached | stage/verify binary; expect exit 42 |
| `[upgrade] candidate … refused: …` | staging rule failed | fix the candidate |
| `COMMISSION-ANNOUNCE …` | commission change scheduled | inform delegators |
| `[consensus] view change` repeatedly | rounds not converging | check proposer/peers; §failure runbook |
| `rejected proposal` | proposer/order-root/shard-head refusal | inspect the named reason |
| `FINALIZE-BLOCKED` | finality path blocked | critical |
| `lacks a validator quorum` | not enough reachable power | restore peers / validators |

## Liveness watchdog

Two layers:

### Cluster watchdog

```bash
scripts/cluster-watchdog.sh --interval 60
```

Polls every 60 s. Alerts (stdout+stderr, exit 1) when a node is down,
crash-looping, on a different topic, above the inode threshold, or when the
masterchain tip has not advanced for N seconds. Auto-heals only the safe cases:
restart a dead unit, run the orphan sweeper on inode pressure. It **reports**
topic drift, config drift, tip stalls and stale locks.

### Single-host stall watchdog

`stall_watchdog.sh` restarts via `stell-node.sh` after **180 s** of flat
heights. Use it only for a single-host deployment; on a multi-node cluster the
cluster watchdog is the right tool.

### Read-only health check

```bash
scripts/health_check.sh
scripts/health_check.sh --interval 10 --rpc "8545" --disk / --warn 85 --crit 95
```

It samples `stell_blockNumber` twice, `stell_mempoolSize` once, `df` on the
given path, and scans the journal for refusing patterns. Exit codes: `0`
healthy, `1` degraded, `2` down or bad usage. It writes nothing.

## Warning signs before an outage

- `stell_syncing` true for longer than a normal catch-up;
- `stell_blockNumber` advancing but `stell_getStateRoot` differing from peers;
- `infnode_connections_active` below the configured peer count with
  `reconnects_total` climbing;
- `stell_consensus_round` rising while height stays flat;
- `stellereum_mempool_size` growing while height stays flat;
- inode use above 80 %;
- `persist queue full` in stderr;
- a validator missing from `stell_getValidators` for more than a few heights;
- `/readyz` `failed_checks` non-empty on any node.

## Dashboard layout

A minimal dashboard:

1. **Row 1 — chain:** `stellereum_block_height` derivative, `stell_ready`,
   `stell_consensus_round`, `stell_fork_total`.
2. **Row 2 — agreement:** per-node `stell_getStateRoot` (table), height per
   node, `stell_getValidators` quorum/fragile.
3. **Row 3 — pool:** `stellereum_mempool_size`,
   `stell_mempool_sealed/plain`, mev counters.
4. **Row 4 — host:** `df -i`, `df -h`, `du -sh data/store`, journal error rate.
5. **Row 5 — network:** `infnode_connections_active`, reconnects, published vs
   delivered.

## Next

Pair these signals with the incident procedures in [Operations](/nodes/operations). [Indexer REST](/api/indexer-rest#health-and-readiness) covers the separate indexer health endpoint.
