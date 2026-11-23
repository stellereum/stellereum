# Observability — live 4-validator cluster

Prometheus + Alertmanager + Grafana + node_exporter on the build host, scraping
the four validators' `/metrics` endpoints without exposing them to the network.

The nodes publish Prometheus text at `GET /metrics` on
`STELL_EXPLORER_LISTEN=127.0.0.1:8080`. That binding is deliberate:

- `/metrics` is unauthenticated and carries peer ids, validator ids, heights and
  host performance data. It has no business on a public interface.
- The nodes' public exposure is the RPC/gateway surface, not the metrics one.
- A remote Prometheus therefore cannot scrape `node:8080` directly. A is reached
  over SSH, C over SSH on port 2222, D over SSH, B is local to this host.

So the collector runs next to the tunnels:

| Node | Where | Local scrape target | Path |
| --- | --- | --- | --- |
| A | `root@212.113.103.105:22` | `http://127.0.0.1:9080/metrics` | SSH tunnel |
| B | this host (systemd `--user`) | `http://127.0.0.1:8080/metrics` | direct |
| C | `root@213.21.246.5:2222` | `http://127.0.0.1:9081/metrics` | SSH tunnel |
| D | `root@138.124.102.200:22` | `http://127.0.0.1:9082/metrics` | SSH tunnel |

`9083` is left free for a fifth endpoint (standby/observer). Hosts and ssh
options are read from `scripts/cluster-nodes.conf`; nothing is duplicated here.

## Files

```
ops/observability/
  docker-compose.yml        prometheus, alertmanager, grafana, node-exporter
  prometheus.yml            scrape jobs (stell-nodes, node, prometheus, alertmanager)
  alerts.yml                canonical Prometheus rules for the cluster
  alertmanager.yml          null receiver by default + commented Telegram shape
  .env.example              copy to .env (0600); no secret is committed
  grafana/provisioning/     datasource + dashboard provider
  grafana/dashboards/       stellereum-observability.json (12 panels)
  textfile/                 drop stell_cluster_liveness.prom here for node_exporter
scripts/observe-local.sh    start/stop/status/--check for the A/C/D tunnels
```

`ops/alert_rules.yaml` remains the registry-only reference; it points here and
does not duplicate these thresholds. `ops/alerts.md` is the older runbook and
has a pointer section for the alerts below.

## Bring it up

Prerequisites: Docker Engine + Compose v2, `ssh` access to A/C/D with keys
(`BatchMode=yes` — no password prompts), and a `curl` on the host.

```bash
cd /home/imm/stellereum-project

# 1. tunnels first, so Prometheus has something to scrape
./scripts/observe-local.sh start
./scripts/observe-local.sh --check        # must print RESULT 4/4 nodes reachable

# 2. stack
cd ops/observability
cp -n .env.example .env
chmod 600 .env
$EDITOR .env                              # set GRAFANA_ADMIN_PASSWORD, optionally Telegram
docker compose config -q                  # fails if the password is unset
docker compose up -d
docker compose ps
```

Grafana: <http://127.0.0.1:3000> (admin / the password in `.env`).
Prometheus: <http://127.0.0.1:9090>. Alertmanager: <http://127.0.0.1:9093>.

All four services run with `network_mode: host` and bind `127.0.0.1`
explicitly. That is what makes `localhost:9080-9082` (the tunnels) and
`localhost:8080` (B) reachable from inside the containers. Do not "fix" it by
adding `ports:` or by switching Prometheus to a bridge network — the targets
would then point at the container's own loopback.

### Why no root password in the file

`docker-compose.yml` uses `${GRAFANA_ADMIN_PASSWORD:?…}`: compose refuses to
start without it instead of falling back to `admin/admin`. Telegram credentials
are passed as `${TELEGRAM_BOT_TOKEN:-}` / `${TELEGRAM_CHAT_ID:-}` and consumed
by Alertmanager's `--config.expand-env`; the receiver block stays commented in
`alertmanager.yml`, so the default shape carries no secret at all.

## Tunnel lifecycle

`scripts/observe-local.sh`:

```bash
./scripts/observe-local.sh start     # A/C/D tunnels; prints the four scrape URLs
./scripts/observe-local.sh status    # PIDs; B is local and not managed
./scripts/observe-local.sh stop
./scripts/observe-local.sh restart
./scripts/observe-local.sh --check   # one line per node + RESULT n/4
```

- Uses `autossh -M 0` when installed; otherwise a supervisor loop restarts
  `ssh` after a drop. Both carry `ServerAliveInterval=15`,
  `ServerAliveCountMax=3`, `ExitOnForwardFailure=yes` and `BatchMode=yes`.
- Started under `setsid`, so tunnels survive the script and `stop` can kill the
  whole process group.
- State (pids + per-node logs) lives in `${OBS_STATE_DIR:-$TMPDIR/stell-observe}`.
- Ports are overridable: `OBS_PORT_A`, `OBS_PORT_C`, `OBS_PORT_D`, `OBS_PORT_B`.

## Verifying the stack

```bash
# Prometheus ready
curl -s http://127.0.0.1:9090/-/ready

# four node targets, all up
curl -s http://127.0.0.1:9090/api/v1/targets \
  | jq -r '.data.activeTargets[]
           | select(.labels.job=="stell-nodes")
           | "\(.labels.node)\t\(.health)\t\(.scrapeUrl)"'

# rules loaded
curl -s http://127.0.0.1:9090/api/v1/rules \
  | jq -r '.data.groups[].rules[] | select(.type=="alerting") | .name' | sort -u
```

If a target is down, `./scripts/observe-local.sh --check` separates a dead
tunnel from a dead node: a node that answers `--check` but is `down` in
Prometheus is a configuration problem, not a consensus one.

## Alert catalogue

Every rule has `severity`, `summary`, a `description` naming the runbook anchor
that follows, and a `for:` window. `ops/observability/alerts.yml` is canonical.

### ValidatorQuorumLow

`stell_validator_set_size < 4` **or** `stell_validator_set_fragile == 1`, 2m,
critical. A 3-validator set halts on one outage; fragile means quorum needs
100% of the set. Compare `stell_getValidators` on all four nodes (size, quorum,
fragile) before restarting anything. Quorum values are frozen core — never
"fix" a quorum alert by lowering the threshold.

### ValidatorJailed

`max_over_time(stell_validator_efficiency_ratio[15m]) == 0`, 5m, critical.
The node is scraped but produced none of its expected proposals. Check
`stell_validator_proposals_expected_total` vs `..._produced_total` on the node
(the `stell:validator_proposal_efficiency15m` recording rule is that ratio) and
whether it is still in the active set. Expected > 0 with produced = 0 is the
jailed signature. Do not rotate keys without a human order.

### ValidatorNotVoting

15m mean of `stell_validator_efficiency_ratio` below 0.9 but not zero, 10m,
warning. The node proposes sometimes, so it is in the set; it is losing slots.
Cross-check `stell_proposer_missed_total`, `stell_propose_gate_blocked_total`
and the apply/CPU panels. This is the early warning before ValidatorJailed.

### NodeOutOfSync

`max_over_time(stell_consensus_height[2m])` more than 50 below the cluster max,
2m, warning. Establish whether the node is advancing (compare deltas, not one
sample). A lagging node that catches up is healthy; a frozen one is BlockStall
plus a separate cause. Do not wipe data; restart only the lagging node when the
runbook says so.

### BlockStall

`delta(stell_consensus_height[60s]) <= 0`, 1m, critical. With
`STELL_MIN_BLOCK_MS=400` a flat minute is a real stall. Read
`stell_consensus_round` and `increase(stell_nil_rounds_total[10m])` first:
round climbing + height flat is a vote/view-change problem, both flat is a dead
loop. Cross-check the other nodes before concluding it is network-wide.

### DiskUsageHigh

`node_filesystem_avail_bytes / node_filesystem_size_bytes` below 20%, 10m,
warning. tmpfs/overlay and container `/etc/*` mounts are excluded. Compare
against `stell_data_dir_bytes` and `stell_snapshot_count`; prune only through
the documented path and only after `scripts/backup_verify.sh` verifies a
snapshot.

### DiskWillFillIn24h

`predict_linear(node_filesystem_avail_bytes[6h], 24h) < 0` while the filesystem
is already > 50% used, 30m, critical. Needs 6h of history; after a fresh start
the rule is blind until then. The 50% guard keeps noise on a near-empty disk
from paging.

### InodesHigh

`node_filesystem_files_free / node_filesystem_files` below 20%, 10m, warning.
A full inode table makes the filesystem read-only and silently drops consensus
writes (Node C hit 655360/655360). Run the orphan sweeper, then re-check
`node_filesystem_files_free`; do not delete live store data.

### ApplySlow

p95 of `stell_apply_seconds` above 50ms for 10m, warning. Apply runs inside the
consensus tick and the proposer gate refuses to build while an apply is in
flight, so this widens block gaps. Check host CPU/IO and `PersistQueueBacklog`
before blaming consensus.

### CpuPerBlockHigh

p95 of `stell_cpu_per_block_seconds` above 400ms for 15m, warning. Includes
background threads. Compare `rate(stell_falcon_sign_total[5m])` with its 1h
baseline: a signing increase points at redundant work, a flat rate with high
CPU points at host contention or a build on the box.

### PersistQueueBacklog

`stell_persist_queue_depth > 100` for 5m, warning. Writes are not keeping up
with apply. Check disk latency/free space. If
`stell_persist_queue_dropped_total` also increases, jobs are already being
shed — that is the hard failure and the disk must be replaced or the workload
moved.

### DivergenceDetected

Any `increase(stell_divergence_total[5m])`, 1m, critical. A proposal's
post-state root disagreed with ours on the same finalized hash. Stop
transacting, preserve logs and data, take a verified snapshot, and compare
`stell_getStateRoot` at a common height across nodes **before** restarting.

### ForkDetected

Any `increase(stell_fork_total[5m])`, 1m, critical. A block conflicting with
this node's finalized chain was seen. Capture the height/hash from the journal;
compare heights and state roots across nodes. Do not restart into the same
state blindly.

### NodeMetricsUnreachable

`up{job="stell-nodes"} == 0` for 3m, critical. Separates "node is down" from
"tunnel is down": run `./scripts/observe-local.sh --check`. A tunnel failure is
an observability incident, not a consensus one. Alertmanager inhibits this
node's other alerts while it fires, to avoid stale-series noise.

### FalconSignRate

Informational. Fires when `rate(stell_falcon_sign_total[5m]) == 0` while
`stell_ready == 1`, for 10m. Signing dominates CPU on a 1-vCPU validator, so
zero while ready means the node is not voting/proposing (observer mode, wrong
keys, stalled loop). The raw rate is the "Falcon signatures / s" dashboard
panel and the `stell:falcon_sign_rate5m` recording rule. Routed to the null
receiver by default.

## Wave gate (acceptance test)

Run from a clean shell on the build host. Criteria: **`--check` prints
`RESULT 4/4 nodes reachable` (exit 0)** and **a test alert reaches the duty
channel**.

```bash
cd /home/imm/stellereum-project
./scripts/observe-local.sh start
./scripts/observe-local.sh --check; echo "check_exit=$?"
# expected:
#   A    OK   http://127.0.0.1:9080/metrics  height=... ready=1
#   ...
#   RESULT 4/4 nodes reachable
#   check_exit=0

cd ops/observability
cp -n .env.example .env && chmod 600 .env
# set GRAFANA_ADMIN_PASSWORD; for the duty-channel half also set
# TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID and uncomment the telegram-duty
# receiver + route in alertmanager.yml.
docker compose config -q
docker compose up -d

# all four node targets must be health=up
curl -s http://127.0.0.1:9090/api/v1/targets \
  | jq -r '.data.activeTargets[] | select(.labels.job=="stell-nodes")
           | "\(.labels.node)\t\(.health)"'
# A  up
# B  up
# C  up
# D  up

# send the test alert (2-minute lifetime, then it auto-resolves)
docker compose exec alertmanager \
  amtool --alertmanager.url=http://127.0.0.1:9093 alert add \
    alertname=WaveGateTest severity=critical node=A \
    --annotation=summary="wave gate: alert delivery check" \
    --end="$(date -u -d '+2 minutes' +%Y-%m-%dT%H:%M:%SZ)"

# it must be visible in Alertmanager ...
docker compose exec alertmanager \
  amtool --alertmanager.url=http://127.0.0.1:9093 alert query alertname=WaveGateTest

# ... and, with Telegram enabled, present in the duty group.
# Resolve early if needed:
docker compose exec alertmanager \
  amtool --alertmanager.url=http://127.0.0.1:9093 alert add \
    alertname=WaveGateTest severity=critical node=A \
    --end="$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)"
```

Gate is green when all of:

1. `./scripts/observe-local.sh --check` exits 0 with `RESULT 4/4 nodes reachable`.
2. The targets API shows nodes A/B/C/D `up` under job `stell-nodes`.
3. `amtool alert query alertname=WaveGateTest` returns the alert **and** (with
   Telegram configured) the message is visible in the duty channel.
4. `curl -s localhost:9090/api/v1/rules | jq -r '.data.groups[].rules[].name'`
   includes `ValidatorQuorumLow`, `BlockStall`, `DiskUsageHigh`,
   `DivergenceDetected`.

## Known limits

- **Remote host disks are not monitored by this stack.** node_exporter runs on
  the build host, so `DiskUsageHigh`, `InodesHigh` and `DiskWillFillIn24h`
  describe the build host only. Covering A/C/D means running node_exporter on
  each validator and adding a second forward
  (`-L 127.0.0.1:9180:127.0.0.1:9100` per node) plus targets; do not expose
  node_exporter publicly. Until then, validator disk pressure is caught by
  `scripts/cluster-watchdog.sh` (inode warning/hard thresholds from
  `cluster-nodes.conf`).
- `BlockStall` keys on `stell_consensus_height`, which the consensus engine
  advances on finality; a node that is alive but isolated will also stop
  incrementing it. Use `NodeOutOfSync` for "behind but moving".
- `DiskWillFillIn24h` needs 6h of node_exporter history before it can fire.
- `--check` proves the metrics endpoint answers, not that consensus is healthy:
  it prints `height` and `ready` so a frozen height is visible, but the alert
  rules and `scripts/cluster_liveness.sh` remain the health authority.
- The SSH tunnels authenticate as `root` because that is how the cluster is
  administered today. Use key-only auth; the helper passes `BatchMode=yes` and
  never prompts for a password.
