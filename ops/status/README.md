# Stellereum Standalone Status Service (`ops/status/`)

Zero-dependency Python HTTP service (`ops/status/status_server.py`) that polls the Stellereum validator cluster + public RPC load balancer on a background interval, keeps a rolling 10-minute ring buffer of snapshots, and serves a public status page, JSON API, health/readiness probes, and Prometheus metrics.

Only public read-only endpoints are queried (`eth_blockNumber`/`stell_blockNumber`, `stell_syncing`, `stell_getStateRoot`, `stell_getValidators`, `stell_mempoolSize`, `stell_chainId`, `stell_nodeId`, `/api/version`, `/readyz`, `/metrics`). Unreachable or invalid nodes always report `ok: false`, `status: "unknown"`, `height: null`, and an explicit `error` string — heights and metrics are never fabricated.

## Quick start

Run once and print the JSON snapshot:

```bash
python3 ops/status/status_server.py --once
```

Run the HTTP server (binds `127.0.0.1:8095` by default):

```bash
python3 ops/status/status_server.py
```

Custom targets (comma-separated, JSON array, or path to a JSON targets file):

```bash
STELL_STATUS_TARGETS='A=http://127.0.0.1:8545,B=http://127.0.0.1:8546,RPC-LB=https://rpc.stellereum.org' \
  STELL_STATUS_EXPECTED_VALIDATORS=2 \
  python3 ops/status/status_server.py --listen 127.0.0.1:8095
```

## HTTP endpoints

| Path | Purpose | Status codes |
|---|---|---|
| `/` | Self-contained responsive HTML status dashboard (auto-refreshes) | `200` |
| `/api/status.json` (alias `/status.json`) | Full JSON cluster + per-node snapshot | `200` once initial poll finishes, `503` while initializing |
| `/health` (alias `/healthz`) | Liveness probe | `200` |
| `/readyz` | Readiness probe (reports `ready: true` after first poll) | `200` ready, `503` initializing |
| `/metrics` | Prometheus exposition metrics (`stell_status_*`) | `200` |

## Exported Prometheus metrics (`/metrics`)

- `stell_status_up` (`1` after first poll completes, `0` before)
- `stell_status_cluster_healthy` (`1` when `HEALTHY`, `0` when `DEGRADED` or `DOWN`)
- `stell_status_cluster_verdict` (`2=HEALTHY`, `1=DEGRADED`, `0=DOWN`)
- `stell_status_active_validators` / `stell_status_expected_validators`
- `stell_status_finals_rate_per_min` (rolling 10-minute blocks/min)
- `stell_status_cluster_height`
- `stell_status_cluster_block_interval_p99_ms` / `stell_status_cluster_block_interval_avg_ms`
- `stell_status_target_up{node,role}`, `stell_status_target_height{node,role}`, `stell_status_target_efficiency{node}`, `stell_status_target_block_interval_p99_ms{node}`

## Environment variables & CLI flags

| Env var | CLI flag | Default | Description |
|---|---|---|---|
| `STELL_STATUS_LISTEN` | `--listen` | `127.0.0.1:8095` | Bind address `host:port` |
| `STELL_STATUS_TARGETS` | `--targets` | A/B/C/D + `https://rpc.stellereum.org` | JSON array, JSON file path, or `node=url,...` list |
| `STELL_STATUS_TARGETS_FILE` | `--targets-file` | unset | Path to JSON targets array (`node`, `name`, `role`, `rpc_url`, `explorer_url`, `validator_id`) |
| `STELL_STATUS_INTERVAL` | `--interval` | `15` | Background poll interval in seconds |
| `STELL_STATUS_TIMEOUT` | `--timeout` | `3` | Per-HTTP/RPC request timeout in seconds |
| `STELL_STATUS_HISTORY` | `--history` | `40` | Rolling snapshot ring buffer size (`40 * 15s = 10m`) |
| `STELL_STATUS_EXPECTED_VALIDATORS` | `--expected-validators` | `4` | Expected active validator count for `HEALTHY` |
| `STELL_STATUS_LOG_LEVEL` | — | `INFO` | Python logging level |

## Cluster verdict rules

- **`DOWN`**: all targets unreachable, zero validators reachable, or active/unjailed validators below BFT quorum (`(expected * 2) // 3 + 1`, or reachable voting power `< quorum` from `stell_getValidators`).
- **`DEGRADED`**: quorum holds, but at least one target is unreachable, a validator is jailed or out of the active set, `validator_set_fragile` is true, `syncing == true`, `ready == false`, RPC vs `/metrics` heights disagree, efficiency `< 0.9`, chain ID mismatch, height lag `> 5` blocks, or `finals_rate_10m == 0` over the stall window (`120s`).
- **`HEALTHY`**: quorum holds and all checks pass.

## Production deployment

1. **Systemd service**: copy `ops/status/stell-status.service` to `/etc/systemd/system/stell-status.service`, adjust paths/`User` if your checkout is not at `/opt/stellereum`, optionally create `/etc/stellereum/stell-status.env`, then:

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin stell-status || true
   sudo cp ops/status/stell-status.service /etc/systemd/system/stell-status.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now stell-status.service
   ```

2. **Nginx reverse proxy**: install `deploy/nginx/status.stellereum.org.conf` into `/etc/nginx/sites-available/status.stellereum.org.conf`, symlink into `/etc/nginx/sites-enabled/`, verify TLS certs, and reload:

   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

3. **Prometheus & Grafana**:
   - Add a scrape job in `ops/observability/prometheus.yml` targeting `127.0.0.1:8095` (`metrics_path: /metrics`).
   - Import `ops/status/grafana-public-status.json` into Grafana (uses datasource UID `prometheus`).

## Verification

```bash
python3 -m py_compile ops/status/status_server.py
python3 -m unittest discover -s ops/status -v
python3 -m json.tool ops/status/grafana-public-status.json > /dev/null
```
