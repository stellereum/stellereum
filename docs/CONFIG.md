# Stellereum Node Configuration (`stellereum.toml`)

Stellereum separates P2P transport configuration (`infnode` YAML via `-c` / `--config`) from node policy, RPC, storage, and telemetry settings (`stellereum.toml` via `--node-toml` or `STELL_*` environment variables).

> **Important:** `-c` / `--config` on `stellereum run` is reserved for `infnode`'s YAML config (`config.yaml`). Always use `--node-toml <PATH>` (or `STELL_NODE_TOML`) for Stellereum TOML config.

---

## 1. Precedence & Discovery

Settings are resolved in strict priority order (highest to lowest):

1. **CLI flags** (e.g. `-t` / `--no-telemetry`)
2. **Environment variables** (`STELL_*`) — *always* override TOML
3. **TOML config file** (`NodeTomlConfig`), discovered via:
   - `--node-toml <PATH>` (fails loudly if missing)
   - `STELL_NODE_TOML=<PATH>` (fails loudly if missing)
   - `./stellereum.toml` in the working directory (auto-discovered if present)
4. **Compiled defaults**

Implementation note: `main()` loads the TOML file and calls `NodeTomlConfig::apply_defaults_to_env()` **before** `runtime_limits::detect()` and **before** spawning the Tokio runtime. `apply_defaults_to_env()` only sets an environment variable when `std::env::var_os(key).is_none()`, guaranteeing that existing `STELL_*` environment overrides always win without rewriting downstream call sites.

Every TOML struct uses `#[serde(deny_unknown_fields)]`, so typos or unknown sections fail loudly at load time.

---

## 2. Validating Configuration (`stellereum config check`)

Validate your TOML + current environment without starting a node:

```bash
# Auto-discovers $STELL_NODE_TOML or ./stellereum.toml if present
stellereum config check

# Validate an explicit file (errors if missing)
stellereum config check --file ./stellereum.toml

# Machine-readable JSON output (secrets redacted)
stellereum config check --file ./stellereum.toml --json
```

`config check` exits non-zero if there are parse errors or validation errors, and prints each setting's effective value alongside its source (`toml`, `env`, or `default`). Secret values (`rpc.auth_token`, `faucet.faucet_key`, `faucet.faucet_token`, `faucet.turnstile_secret_key`, `signer.remote_signer_token`) are redacted as `<redacted>`.

### Validation Rules

**Errors (startup / `config check` fails):**
- `tempo.min_block_ms <= tempo.round_timeout_ms`
- `tempo.tick_ms` in `10..=1000`
- `tempo.straggler_grace_ms <= tempo.straggler_grace_cap_ms` (when both > 0)
- If `storage.archive == false`, `storage.keep_blocks > 0`
- `faucet.faucet_drip_stell <= faucet.faucet_lifetime_cap_stell`
- `consensus.chain_id > 0`
- `signer.remote_signer_url` (when set) must start with `http://` or `https://`
- Unparseable numeric/boolean `STELL_*` environment overrides

**Warnings (non-fatal, printed loudly):**
- `rpc.rpc_listen` is non-loopback and `STELL_RPC_AUTH_TOKEN` (`rpc.auth_token`) is unset
- `storage.schema_downgrade_allowed == true` (`STELL_ALLOW_SCHEMA_DOWNGRADE=1`)
- `consensus.pure_pq == false` (ignored: FULL-PQ mode is always enforced)
- `storage.snapshot_interval < 50` (clamped to 50)
- Only one of `STELL_TURNSTILE_SITE_KEY` / `STELL_TURNSTILE_SECRET_KEY` is set

---

## 3. Telemetry & `-t` / `--no-telemetry`

Telemetry/status-banner exposure can be disabled in three equivalent ways:

1. CLI flag on `run`: `stellereum run -t` or `stellereum run --no-telemetry`
2. TOML: `[telemetry]\nenabled = false` (or top-level shorthand `telemetry = false`)
3. Environment variable: `STELL_NO_TELEMETRY=1`

### What `-t` / `--no-telemetry` disables
- Disables non-essential human telemetry/status-banner exposure: `GET /status` returns `404 Not Found` (`status page disabled (STELL_NO_TELEMETRY=1)`).

### What remains active
- `GET /health` (structured JSON health verdict)
- `GET /healthz` (process liveness probe)
- `GET /readyz` (readiness probe: `no_peers`, `no_finality`, `finality_stalled`, `height_zero`, `height_stalled`)
- `GET /metrics` (Prometheus scrape endpoint, including `stell_validator_efficiency_ratio`, `stell_block_interval_seconds`, and `stell_ready`)

Keeping `/health`, `/healthz`, `/readyz`, and `/metrics` active ensures load balancers, systemd watchdogs, and Prometheus alerting never break when `-t` is enabled.

---

## 4. Sections Reference

See [`stellereum/stellereum.toml.example`](../stellereum/stellereum.toml.example) for a complete annotated example covering all 10 sections:

- `[tempo]` — `STELL_TICK_MS`, `STELL_MIN_BLOCK_MS`, `STELL_ROUND_TIMEOUT_MS`, `STELL_ROUND_ZERO_TIMEOUT_MS`, `STELL_DOWN_PROPOSER_TIMEOUT_MS`, `STELL_STRAGGLER_*`, `STELL_CATCHUP_*`, `STELL_RETRO_*`, `STELL_DEADLOCK_TIMEOUT_SECS`
- `[consensus]` — `STELL_CHAIN_ID`, `STELL_OBSERVER`, `STELL_WORKCHAIN_OBSERVER`, `STELL_NEW_CHAIN`, `STELL_SHARDS`, `STELL_EXPERIMENTAL_SHARDS`, `STELL_PURE_PQ`, `STELL_AUTO_UPGRADE`, `STELL_WAIT_SUPERMAJORITY*`, `STELL_GOV_ALLOW_MULTINODE_WRITES`, `STELL_*_ACTIVATION_HEIGHT`, `STELL_MIN_BOND_BUFFER`, `STELL_SLASH_EJECT_WARN_GAP`, `STELL_MEV_*`
- `[storage]` — `STELL_DATA_DIR`, `STELL_ARCHIVE`, `STELL_KEEP_BLOCKS`, `STELL_SNAPSHOT_INTERVAL`, `STELL_SLED_*`, `STELL_ALLOW_SCHEMA_DOWNGRADE`, `STELL_VALIDATOR_SET_MAX_LAG`, `STELL_MAX_*`, `STELL_SNAPSHOT_CHUNK_ACCOUNTS`, `STELL_UPGRADE_HALT_MARKER`, `STELL_CNVRF_V3_DIR`
- `[network]` — `STELL_DNS_SEEDS`, `STELL_PEER_PQ_KEYS`, `STELL_SEND_TIMEOUT_MS`, `STELL_BROADCAST_JOIN_MS`, `STELL_PROBE_EVICT_AFTER`, `STELL_DIAL_*`, `STELL_CONS_*`, `STELL_INBOUND_*`, `STELL_DHT_*`, `STELL_REPL_*`
- `[rpc]` — `STELL_RPC_LISTEN`, `STELL_EXPLORER_LISTEN`, `STELL_RPC_AUTH_TOKEN`, `STELL_RATE_LIMIT_PER_SEC`, `STELL_STANDALONE_RATE_LIMIT`, `STELL_ESTIMATE_FEE_RATE_LIMIT`, `STELL_WS_*`, `STELL_HTTP_EXPENSIVE_READ_CONCURRENCY`, `STELL_SSE_IDLE_TIMEOUT_SECS`, `STELL_TRUSTED_PROXY_CIDRS`, `STELL_XFF_MODE`, `STELL_TRUST_LOOPBACK_FORWARDED`
- `[mempool]` — `STELL_MEMPOOL_CAP`, `STELL_MEMPOOL_PER_SENDER`
- `[faucet]` — `STELL_FAUCET*`, `STELL_PUBLIC_DRIP_*`, `STELL_TURNSTILE_*`, `STELL_DEV_UNSAFE_TESTKEY`
- `[signer]` — `STELL_FALCON_KEY_FILE`, `STELL_REMOTE_SIGNER_*`, `STELL_KEY_PLAINTEXT`, `STELL_KEY_PROMPT`
- `[telemetry]` — `STELL_NO_TELEMETRY`, `STELL_LIVENESS_ALARM_MS`, `STELL_LOG_MAX_*`, `STELL_READY_*`, `STELL_HEALTH_*`
- `[execution]` — `STELL_PARALLEL_EXEC`, `STELL_PARALLEL_PLAN_CHUNK`, `STELL_RUNTIME_WORKERS`, `STELL_RUNTIME_MAX_BLOCKING`, `STELL_REGISTER_SOURCE`
