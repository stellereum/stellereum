# Testnet readiness — operator checklist (3-node testnet)

> 2026-11-04 changelog: legacy-genesis env knob marked removed/inert and VRF arming marked retired/inert in §3 env inventory (citations in text).

> Scope: READ-ONLY audit of the repo. Nothing here was verified against a live
> host (no ssh, no systemctl, no restarts). Anything that requires a live host
> to confirm is marked **UNVERIFIED**.
>
> Task scoping: this file only. No code/config changes were made.
> Live paths (`multinode/`, `/root/*`) were not touched.
>
> How to use this file: §1–§7 = "what exists" (file:line/command for each
> claim). §8 = what's missing, ranked by risk. Start every shift with the
> §8 top-5 and the two commands in §6.

Reference topology: `scripts/cluster-nodes.conf` currently describes a
**4-validator** cluster (A/B/C/D). The 3-node testnet reuses the same tooling
with `STELL_NODES` narrowed (e.g. `STELL_NODES="A B C"`) — confirm which three
hosts/units/env files are canonical before operating. **UNVERIFIED** which
three hosts the testnet actually runs on.

---

## 1. systemd units (shape only — unit files for C/D are not in the repo)

### What EXISTS

- Node unit shape (A and B only in-repo):
  `stellereum/scripts/systemd/stell-nodeA.service:1-50`,
  `stellereum/scripts/systemd/stell-nodeB.service:1-50`:
  - `Restart=always` + `RestartSec=5` (sled lock + ports release).
  - Crash-loop guard: `StartLimitIntervalSec=300` / `StartLimitBurst=5` —
    stops retrying, operator investigates with
    `journalctl -u <unit> -e` + `systemctl reset-failed`.
  - `User=root Group=root` (key material lives under `/root`, mode-600).
  - `WorkingDirectory=/root/nodeA` (relative `./data`, `./keys`,
    `--config node.yaml` resolve from here).
  - `EnvironmentFile=/root/env.A` with **no `-` prefix**: a missing env file
    FAILS the unit instead of starting with wrong ports/tokens.
  - `ExecStart=/root/stellereum/target/release/stellereum run --config node.yaml --shard 1`
    — note: the scripted deploy path (`scripts/stell-sync.sh:197-229`)
    moves the binary to `$NODE_DIR/stellereum(.new)` instead; reconcile the
    unit's `ExecStart` with where `deploy` actually puts the binary
    **UNVERIFIED** on live hosts.
  - Resource caps: `MemoryMax=2G`, `CPUQuota=80%` (tuned for a 1-vCPU/3.8 GB
    box; see `stellereum/docs/OPERATIONS.md:89-138` — 1 vCPU is explicitly
    insufficient for a sharded validator).
  - Logging: `StandardOutput=journal`, `StandardError=journal`,
    `SyslogIdentifier=stell-nodeA`, `PrivateTmp=true`.
- Sweeper units (run on **every** node):
  `scripts/systemd/stell-node-prune.service:1-48`
  (`Type=oneshot`, `WorkingDirectory=/root/nodeC` — edit per node,
  `ExecStart=... node-prune-cron.sh --dir /root/nodeC --grace-seconds 21600`,
  `TimeoutStartSec=3600`, `Nice=10`, `IOSchedulingClass=idle`),
  `scripts/systemd/stell-node-prune.timer:1-22`
  (`OnCalendar=hourly`, `RandomizedDelaySec=600`, `Persistent=true`).
  Install per `scripts/README.md:62-71`.
- `scripts/cluster-nodes.conf:26-56`: A/C/D are `system` scope,
  B is `systemctl --user` scope (`NODE_B_SCOPE=user`). Probes, doctor, and
  the watchdog all branch on this scope.

### What is MISSING

- **No `stell-nodeC.service` / `stell-nodeD.service` unit files in the repo.**
  `scripts/cluster-nodes.conf:41-56` references them, and the fault runbook
  references `/etc/systemd/system/stell-node*.service` on hosts, but only
  A/B shapes are shipped. **UNVERIFIED** whether C/D units exist live and
  whether they match the A/B shape (Restart policy, StartLimit, caps,
  journal mode, EnvironmentFile strictness).
- **No shipped `enabled` audit.** `preflight` checks `service_enabled`
  (`scripts/stell-sync.sh:877-884`), but there is no inventory file stating
  which units must be enabled on which host — a disabled unit does not come
  back after reboot (incident-5 class).
- **No journald cap shipped in-repo.** The join path mentions a 500M journald
  drop-in + logrotate (`stellereum/docs/OPERATIONS.md:974-978`), but no
  `journald.conf.d/` file is shipped for the 3-node testnet. Journal growth
  (~1 GB, `stellereum/scripts/monitor/RUNBOOK.md:196-204`) is the biggest
  disk driver.

---

## 2. Ops scripts (`scripts/`, `scripts/tools/stelops`)

### What EXISTS

| Command | File:line | Writes? |
|---|---|---|
| `stell-sync.sh preflight` — fail-closed deploy gate (reachability, topic, STELL_SHARDS, chain-id, genesis/epoch, timeouts, retention, base-fee, inodes, binary-in-target-dir, enabled+active, RPC answers) | `scripts/stell-sync.sh:748-918`, topology `scripts/cluster-nodes.conf:1-104` | no |
| `stell-sync.sh health` — validator set/power/quorum/fragile, shard heads, per-shard tip, indexer tip, RPC latency, per-node cluster table, cluster problems; exit 0/1 so it works as a cron/alert probe | `scripts/stell-sync.sh:250-722` | no |
| `stell-sync.sh topic <node>` — expected vs subscribed pubsub topic | `scripts/stell-sync.sh:931-963` | no |
| `stell-sync.sh lockclear <node> [--force]` — plan vs execute; stops node, verifies lock ahead of peers, clears, backs up to `consensus-checkpoint.bak.<ts>`, restarts; never touches finalized pointer | `scripts/stell-sync.sh:992-1147` | **yes (store)** |
| `stell-sync.sh doctor [node]` — delegates to `doctor.sh` locally or pipes it over ssh (never installs a stale copy) | `scripts/stell-sync.sh:1153-1183`, `scripts/doctor.sh:1-491` | no |
| `stell-sync.sh sync/auto-heal/deploy/restart/status` — HTTP fast-sync from `https://rpc.stellereum.org/snapshot/latest.tar.zst`, lag-triggered heal, atomic parallel binary deploy, cluster restart | `scripts/stell-sync.sh:129-229`, `scripts/stell-sync.sh:1288-1327` | **yes** |
| `doctor.sh` — service, inodes, orphans, checkpoint (store or fallbacks), topic from `subs.json`→`kv.json`→journal, binary path/hash/target-dir, key format, chain-id/base-fee/tip, named drift list; `--json` for machines | `scripts/doctor.sh:1-491` | no |
| `lib/nodeprobe.sh` — the `key=value` probe all of the above is built on; POSIX, read-only by construction; covers 20+ `STELL_*` env values, inodes, chunks, topic, lock, keys, RPC | `scripts/lib/nodeprobe.sh:1-437` | no |
| `cluster-watchdog.sh` — `--interval/--once/--no-heal/--json/--stall-seconds/--state-file`; alerts DOWN/CRASH-LOOP/topic-drift/inode/stall/DIVERGENCE; **auto-heals only**: dead-service restart + orphan prune; never auto-heals drift/lock/lag/divergence | `scripts/cluster-watchdog.sh:1-398` | **yes (restart, prune)** |
| `node-prune-cron.sh` — orphan-chunk + snapshot-retention sweeper; referenced-set + grace 6h + `--max-kv-age` fail-closed + re-verify + `--max-delete` cap + flock; safe live; idempotent | `scripts/node-prune-cron.sh:1-278` | **yes (deletes garbage)** |
| `tools/stelops` — `checkpoint`, `genesis-root`, `meta`, `doctor` (`--shards/--shard-id/--text`), `clear-lock --force`, `diverge` (offline fork diff incl. snapshot digest); sled-exclusive (fails while node runs = by design); refuses to create a store on a wrong path | `scripts/tools/stelops/src/main.rs:1-761` | **yes (lock only)** |
| `local-cluster.sh` — local N-validator testnet (`run/cluster/node<i>/`), `up/status/stop/start/restart/down/reset/chaos`, read-only toward live | `scripts/local-cluster.md:1-122` | local only |
| `run-observer.sh` — third-party observer bootstrap (writes `observer.yaml` + `env.observer`, snapshot-seeds `data/`) | `scripts/run-observer.sh:1-78` | new host only |
| Gate scripts (NOT ops, but bound the release path) | `scripts/verify_testnet_ideal.sh:1-83`, `scripts/harness_status.sh:1-39`, `scripts/feature_matrix.sh:1-124` | no |

Build the ops tool: `cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml`
(`scripts/README.md:73-82`). `lockclear` stages it to `$STELOPS_REMOTE=/root/stelops`
automatically (`scripts/stell-sync.sh:1050-1070`).

### What is MISSING

- **No periodic scheduling shipped.** `health`/`preflight`/`check.sh` are
  documented as cron/alert probes, and the watchdog documents
  `--interval 60`, but no cron file, systemd timer, or supervisor config for
  the watchdog/health loop itself is shipped. Whether anything actually runs
  them on a schedule is **UNVERIFIED**.
- **No 3-node variant of the topology file.** `cluster-nodes.conf` ships
  4 nodes (A/B/C/D, `STELL_NODES="A B C D"`); the 3-node testnet must define
  its own `STELL_CONF` (or `--nodes`) — no checked-in 3-node conf exists.
- **`deploy`/`restart`/`auto-heal` touch live state over ssh by design.**
  They are correctly excluded from routine readiness use; keep them behind an
  explicit human order (repo rule: live cluster is read-mostly).

---

## 3. Env-var surface (`STELL_*` inventory, repo-read only)

Preflight-enforced (must agree cluster-wide):
`STELL_SHARDS` (`EXPECT_STELL_SHARDS=0,1`, `scripts/cluster-nodes.conf:68`),
`STELL_DOWN_PROPOSER_TIMEOUT_MS` (expect 800),
`STELL_MIN_BLOCK_MS` (expect 50),
`STELL_KEEP_BLOCKS` (expect 8000),
`STELL_ARCHIVE` (expect 0),
`STELL_CHAIN_ID` (expect 5757, frozen once read),
base-fee floor via `STELL_MIN_GAS_LIMIT` (expect 280000 base fee).
The base round timeout is **not** an env setting: `FROZEN_ROUND_TIMEOUT_BASE_MS = 3_000`
is compiled (ruleset v2+; the old `STELL_ROUND_TIMEOUT_MS` is gone), so agreement
means running the same binary/ruleset.

Full inventory seen via repo grep (defaults where the source states one;
live values are whatever the per-node env files hold — **UNVERIFIED** live):

- Consensus/timing: base round timeout compiled `FROZEN_ROUND_TIMEOUT_BASE_MS = 3_000`
  (no `STELL_ROUND_TIMEOUT_MS` env; removed), `STELL_ROUND_ZERO_TIMEOUT_MS` (650),
  `STELL_DOWN_PROPOSER_TIMEOUT_MS` (800), `STELL_MIN_BLOCK_MS` (code default
  50 — `node/policy.rs::DEFAULT_MIN_BLOCK_MS`),
  `STELL_TICK_MS`, `STELL_CATCHUP_BUDGET_MS` (default 250) /
  `STELL_CATCHUP_INTERVAL_MS` (default 30 000; a backstop only — catch-up is
  event-driven and skipped at tip), `STELL_BROADCAST_JOIN_MS` (500),
  `STELL_SEND_TIMEOUT_MS`,
  `STELL_CONS_BCAST_MIN_INTERVAL_MS`, `STELL_CONS_PROBE_MIN_INTERVAL_MS`,
  `STELL_PROBE_EVICT_AFTER`, `STELL_DIAL_BACKOFF_BASE/MAX_MS`,
  `STELL_DIAL_BUDGET_PER_SEC`, `STELL_INBOUND_BULK_BYTES_PER_SEC/BURST`,
  `STELL_STRAGGLER_GRACE/CAP/FRESHNESS_MS`, `STELL_DEADLOCK_TIMEOUT_SECS`
  (300), `STELL_LIVENESS_ALARM_MS`, `STELL_RETRO_PUBLISH_INTERVAL_MS` /
  `STELL_RETRO_BEHIND_WINDOW_SECS`, `STELL_MEV_UNSEAL_WAIT_MS`.
- Sharding/execution: `STELL_SHARDS` (`stellereum/src/sharding.rs:379`),
  `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` (2PC is compiled:
  `XPC_ACTIVATION_HEIGHT = 0`; `STELL_XPC_ACTIVATION_HEIGHT` is deprecated
  and ignored),
  `STELL_WORKCHAIN_OBSERVER`, `STELL_OBSERVER`, `STELL_PARALLEL_EXEC`,
  `STELL_SNAPSHOT_INTERVAL` (default 1000, min 50), `STELL_NEW_CHAIN`
  (`stellereum/src/bootstrap.rs:116`), `STELL_DNS_SEEDS`.
- Retention/storage: `STELL_ARCHIVE` / `STELL_KEEP_BLOCKS` (code default
  50000; conf expects 8000; docs recommend 1000000 — reconcile per §8),
  `STELL_DHT_KEEP_BLOCKS_DEFAULT`, `STELL_DHT_PRUNE_INTERVAL_HEIGHTS`,
  `STELL_DHT_PRUNE_MAX_PER_RUN`, `STELL_DHT_FOREVER_TTL_MS`,
  `INFNODE_KV_DEBOUNCE_MS` (30 min live),
  `INFNODE_PEER_EVICT_COOLDOWN_MS` (60 000; peer suspicion cooldown after 3
  consecutive DHT/direct failures), `STELL_SLED_CACHE_BYTES` (1 GiB),
  `STELL_SLED_FLUSH_MS` (500), `STELL_SLED_COMPRESSION`, `STELL_DATA_DIR`.
- Mempool/fees: `STELL_MEMPOOL_CAP`, `STELL_MEMPOOL_PER_SENDER`,
  `STELL_MIN_GAS_LIMIT`, `STELL_ESTIMATE_FEE_RATE_LIMIT` (5/s),
  `STELL_MIN_BOND_BUFFER`, `STELL_SLASH_EJECT_WARN_GAP`,
  `STELL_VALIDATOR_SET_MAX_LAG` (alias `STELL_LEDGER_FRESHNESS_MAX_LAG`).
- Identity/network: `STELL_RPC_LISTEN`, `STELL_EXPLORER_LISTEN`,
  `STELL_RPC_AUTH_TOKEN` (gates `stell_sendRawTransaction` + 3 governance
  methods), `STELL_FAUCET` / `STELL_FAUCET_KEY` / `STELL_FAUCET_TOKEN` /
  `STELL_FAUCET_IP_MAX_PER_HOUR`, `STELL_PEER_PQ_KEYS`, `STELL_FALCON_KEY_FILE`,
  `STELL_BLS_QC` / `STELL_BLS_KEYS_FILE` / `STELL_BLS_KEYS_INLINE` /
  `STELL_BLS_SK_SEED` / `STELL_BLS_POP_REQUIRED`,
  `STELL_VRF_ACTIVATION_HEIGHT` (RETIRED/inert — always Disabled + WARN: `stellereum/src/vrf.rs:201-224`, `stellereum/src/main.rs:2742-2752`) / `STELL_VRF_KEYS`,
  `STELL_PURE_PQ`, ~~legacy-genesis env knob~~ (REMOVED/inert no-op — strict-only keygen: `stellereum/src/post_quantum.rs:1598-1600`; toggle changes nothing: `stellereum/tests/a_crypto_audit_poc.rs:147-174`; guards no longer list it: `stellereum/tests/genesis_guard_tests.rs:60-64`),
  `STELL_DEV_UNSAFE_TESTKEY`, `STELL_TRUSTED_PROXY_CIDRS`, `STELL_XFF_MODE`,
  `STELL_TURNSTILE_SITE_KEY` / `STELL_TURNSTILE_SECRET_KEY`,
  `STELL_REMOTE_SIGNER_URL` / `STELL_REMOTE_SIGNER_TOKEN` (Ed25519-only gap,
  §5), `STELL_CHAIN_ID`, `STELL_AUTO_UPGRADE` (default OFF, §6),
  `STELL_MEV_V4`.
- Observability: `STELL_LOG_MAX_BYTES` (10 MiB) / `STELL_LOG_MAX_FILES` (5),
  `STELL_READY_MAX_STALL_SECS` (30) / `STELL_READY_MIN_PEERS` (1),
  `STELL_RATE_LIMIT_PER_SEC`, `STELL_BUILD_HASH` / `STELL_BUILD_DIRTY`.
- Keys: `STELL_KEY_PASSPHRASE` / `STELL_NODE_PASSPHRASE` /
  `INFNODE_KEY_PASSPHRASE` (first non-empty wins), `STELL_KEY_PLAINTEXT`,
  `STELL_KEY_PROMPT` (TTY-only). See §5.

Local-cluster-only values (`scripts/local-cluster.md:29-48`,
`scripts/run-observer.sh:50-63`) such as `STELL_FAUCET_KEY=1111…1`,
`STELL_KEY_PLAINTEXT=1`, `STELL_NEW_CHAIN=1` must never reach the testnet.

---

## 4. Backup / snapshot

### What EXISTS

- `stellereum/scripts/backup/backup.sh:1-125`: per-node tarball
  `stell-node<A|B>-<UTC-ts>.tar.gz`, mode 600, members
  `node<N>/node.yaml + node<N>/data + node<N>/keys + env.<N>`, `tar -p`
  preserves 600/700, immediate `tar -tzf` verification of all four members,
  retention `--keep N` (default 7). Warns (never fails) when the unit/process
  looks live — hot tarballs can catch sled mid-write, so the documented
  trustworthy path is stop → backup → start
  (`stellereum/scripts/backup/BACKUP.md:44-54`).
- `stellereum/scripts/backup/restore.sh:1-129`: stops the unit itself, scans
  `/proc` for cwd-holders of the sled lock and **refuses** (exit 1, never
  `kill -9`s), rejects archives that are not verifiably that node's backup,
  snapshots current state to `pre-restore-node<N>-<ts>.tar.gz` first (fatal if
  it fails), re-enforces 700/600, does NOT start the node (operator verifies
  then starts by hand).
- `stellereum/scripts/backup/BACKUP.md:1-126` + `stellereum/docs/OPERATIONS.md:708-810`:
  exact backup/restore commands, fingerprint-mismatch triage (backup predates
  a genesis change → restore post-change backup or coordinated whole-`./data`
  wipe; never delete single files), read-only `health_check.sh` complement.
- Consumer-side fast-sync: `stell-sync.sh sync` streams
  `https://rpc.stellereum.org/snapshot/latest.tar.zst` (+ `meta.json`)
  into `<dir>/data/` (`scripts/stell-sync.sh:129-151`); observer bootstrap
  does the same (`scripts/run-observer.sh:65-69`); node-bootstrap gate
  snapshot-syncs state + all domains with tail-anchor + body walk
  (`stellereum/docs/OPERATIONS.md:1020-1078`).

### What is MISSING

- **No scheduled backups.** No cron/timer ships `backup.sh`; cadence,
  ownership, and where `--dir` points (same disk = same failure domain) are
  undefined. Whether any backup exists or is fresh is **UNVERIFIED**.
- **No backup verification or restore drill.** Tarballs are verified at write
  time only; nothing checks restorability, age, or member completeness
  afterwards, and no restore rehearsal is documented for the 3-node layout.
- **No off-host / encrypted copy.** "No backup encryption at rest beyond
  filesystem modes — add age/sops if tarballs ever leave the host"
  (`stellereum/scripts/backup/BACKUP.md:119-126`). Tarballs contain keys +
  env secrets; any off-host copy is plaintext-by-default.
- **Only A/B are covered.** `backup.sh --node` accepts `A|B|all`; there is no
  C (or third-testnet-node) path. Extend or parametrize before relying on it.
- **Snapshot publisher is opaque from the repo.** Nothing in-repo publishes
  `snapshot/latest.tar.zst` (owner, cadence, signing, freshness check all
  absent); fast-sync depends on an artifact this audit could not attribute.
  Treat availability + integrity as **UNVERIFIED**.

---

## 5. Log / metric endpoints

### What EXISTS

- Chain/gateway (`STELL_EXPLORER_LISTEN`, default `127.0.0.1:8080`):
  `GET /healthz` (liveness), `GET /readyz` (200/503 + `failed_checks`:
  `no_peers|no_finality|finality_stalled|height_zero|height_stalled`;
  `STELL_READY_MAX_STALL_SECS=30`, `STELL_READY_MIN_PEERS=1`),
  `GET /metrics` (consensus registry + `stellereum_block_height`,
  `stellereum_mempool_size`, `stellereum_contracts_total`,
  `stellereum_tokens_total`, `stell_ready`) —
  `stellereum/docs/OPERATIONS.md:183-270,813-903`.
- State (polled RPC): `stell_getStateRoot` (the single most valuable check —
  all nodes must match), `stell_getValidators` (set/power/quorum/fragile),
  `stell_blockNumber`, `stell_getShards`, `stell_syncing` (truthful, 5-min
  sightings) — `stellereum/docs/OPERATIONS.md:220-236,352-427`.
- Network (infnode `metrics-listen` in YAML):
  `infnode_connections_active`, `infnode_reconnects_total`,
  `infnode_messages_published_total` vs `_delivered_total`,
  `infnode_frames/bytes_in/out_total`, `infnode_outbox_size/_dropped_total`,
  `infnode_peers_configured`, `infnode_uptime_seconds` —
  `stellereum/docs/OPERATIONS.md:237-266`.
- Disk: external only (`du -sh ./data/store`, `df -i` for inodes, growth-rate
  alerting) — `stellereum/docs/OPERATIONS.md:152-180,267-269`.
- Alerting content shipped: `stellereum/scripts/monitor/prometheus.yml:1-43`
  (scrape snippet, 15 s interval), `stellereum/scripts/monitor/alerts.rules:1-121`
  (`StellNodeDown`, `StellNotReady`, `StellFinalityStalled`, `StellHeightZero`,
  `StellNoPeersSuspected`, `StellDiskFullWarning/Critical`,
  `StellDiskFillingFast`), `stellereum/scripts/monitor/check.sh:1-237`
  (exit 0/1/2 probe, legacy-binary aware),
  `stellereum/scripts/monitor/RUNBOOK.md:1-242` (per-alert diagnose/fix/
  escalate/abort), `stellereum/scripts/logrotate.stellereum:1-15`
  (`current.log`, 50M × 7, `copytruncate`), in-process rotation
  `STELL_LOG_MAX_BYTES`/`STELL_LOG_MAX_FILES`
  (`stellereum/src/metrics.rs:1392-1456`).

### What is MISSING

- **Log pipeline for the journal era is unshipped.** New units log to the
  journal; `logrotate.stellereum` covers only legacy `current.log`. Journal
  caps, forwarding, and retention for the 3-node hosts are undefined
  (see §1). Persist-queue drops and `[rpc] server error` go to **stderr**,
  not structured log (`stellereum/docs/OPERATIONS.md:166-180`) — a deployment
  that ships only the structured log misses them.
- **Known observability gaps (in-repo admissions):** both live nodes shared
  one `:8080` gateway port so per-node attribution was impossible
  (`stellereum/scripts/monitor/prometheus.yml:9-15`) — confirm the 3-node
  ports are split (**UNVERIFIED**); **no peer-count metric** is exported, so
  `StellNoPeersSuspected` is best-effort (`alerts.rules:22-27`); legacy
  binaries answer 404 on `/healthz`/`/readyz` with no `stell_ready`
  (`RUNBOOK.md:10-16`, `check.sh:21-25`).
- **No dashboards.** Prometheus snippet + rules exist; no Grafana/dashboard
  JSON ships. Health-screen fields (fragile quorum, per-shard tips, indexer
  lag, RPC latency, cluster table) have no time-series home.
- **No alert delivery.** Rules define severity + runbook links; no
  Alertmanager/receiver (PagerDuty/Opsgenie/webhook) config ships. Whether
  anything pages is **UNVERIFIED**.
- **No inode / sweeper-effectiveness alert in Prometheus.** Inode thresholds
  exist only in `preflight`/`health`/`watchdog` (warn 70 / hard 85 in
  `cluster-nodes.conf:84-85`; docs say warn 80/crit 90 in
  `OPERATIONS.md:128-135` — reconcile). Nothing pages on inode growth rate
  or sweeper failure.

---

## 6. Key management

### What EXISTS

- Layout/permissions: `./keys` (0700, files 0600, enforced — node refuses
  otherwise), `identity.key` (Ed25519 validator identity),
  `e2e.key` (X25519 transport), `falcon.key` (Falcon-512 PQ vote half) —
  `stellereum/docs/OPERATIONS.md:1192-1310`, probed by
  `scripts/doctor.sh:340-349` and `scripts/lib/nodeprobe.sh:394-410`
  (`key_format`, `key_files`, validator ids from `node.yaml`).
- Encryption at rest (default): `enc2:` = Argon2id (64 MiB, t=3, p=4) +
  XChaCha20-Poly1305. Precedence: first non-empty of
  `STELL_NODE_PASSPHRASE` → `STELL_KEY_PASSPHRASE` →
  `INFNODE_KEY_PASSPHRASE` (`stellereum/src/node_keys.rs:31-77`).
  `STELL_KEY_PLAINTEXT=1` is an explicit opt-out; `STELL_KEY_PROMPT=1` is
  TTY-only so units never block. Fail-closed messages + symptom map in
  `OPERATIONS.md:1261-1310,1904-1953`. Live testnet nodes run plaintext
  (docs) — confirm for the 3-node set **UNVERIFIED**.
- Env hygiene: passphrases via systemd `EnvironmentFile=` (e.g.
  `/etc/stellereum/keys.env`, 0600), never shell history/CI/logs; key backups
  are useless without the passphrase (ciphertext) —
  `OPERATIONS.md:1226-1245`.
- Falcon-512 FIPS-206 migration: pre-FIPS keys are incomplete-NTRU but still
  load/sign with unchanged address; `keys rotate-falcon --force` migrates to
  a complete key **but changes the validator address** → requires on-chain
  re-bond + set rotation, one node at a time with quorum checked before/after
  (`OPERATIONS.md:1312-1400`). **Remote signers do not change this:**
  `STELL_REMOTE_SIGNER_URL` is Ed25519-only; the Falcon half still signs
  locally (`OPERATIONS.md:1342-1347`).

### What is MISSING

- **No Ed25519 identity rotation procedure.** Only Falcon rotation is
  documented; losing/leaking `identity.key` (or its passphrase) has no
  in-repo runbook (quorum-safe replacement order, re-staking, old-key
  revocation). Passphrase rotation (re-encrypt in place) is described
  implicitly, not as a tested procedure.
- **No compromise response.** No documented steps for suspected key leak
  (isolate, rotate, re-bond, audit delegations) or for passphrase loss
  (docs correctly state the key is gone — but the operational consequence for
  a 3-node quorum is unstated).
- **Plaintext posture unconfirmed.** If the 3-node testnet follows the live
  pattern (plaintext keys), that is a deliberate downgrade with no expiry or
  migration ticket in-repo. Confirm on hosts — **UNVERIFIED** (do not print
  key material; `head -c 5 keys/identity.key` shows `enc2:` vs plaintext).

---

## 7. Recovery procedures documented in-repo

- Genesis discipline (§3): fingerprint guard (no override flag), triage order
  (roots → `validators:` → `STELL_FAUCET_KEY` sha256 → binary constants →
  cwd), disposable-vs-precious-chain branches, fresh-dir fork trap
  (`stellereum/docs/OPERATIONS.md:273-351`).
- Stalled-vs-syncing (§4): `stell_syncing`, catch-up jump semantics, rejection
  lines, empty-set fail-closed (`OPERATIONS.md:352-427`); full symptom
  checklists §14.1–§14.5 (`OPERATIONS.md:1821-2083`).
- Offline for maintenance (§5): quorum table (N=2/3 stall on 1 down; N=4
  survives 1), no-solo-finalization, downtime/equivocation slashing economics,
  drain-vs-kill, Ctrl-C-not-`kill -9`, `missed`-counter observability gap
  (`OPERATIONS.md:430-539`).
- Backup/restore + fingerprint mismatch (§8 + BACKUP.md): see §4 above.
- Upgrades (§12): `STELL_AUTO_UPGRADE` default OFF (armed only on literal
  `1`/`true`; typo fails safe to exit-42 halt), candidate staging rules
  (safe name, regular file not symlink, 512 MiB cap, exact sha256, TOCTOU-safe
  private-dir copy, no chmod of candidate, real parent dir),
  operator pre-ratification checklist, rollback procedure (pin previous
  binary + pre-upgrade backup + state-compat check + exact rollback sequence +
  recovery-time expectations) (`OPERATIONS.md:1403-1654`).
- Join/promote/return (§10): `join-network.sh` + `add-peer.sh`,
  `node-bootstrap` 4-stage gate (Observer-only fresh start, snapshot-sync,
  tail-anchor, walk), becoming-validator via coordinated genesis rotation vs
  live staking bond, flown-observer return without `cp -a`
  (`OPERATIONS.md:906-1190`).
- The 3am runbook (§15): 5 invisible incidents → tool map → numbered runbook
  (preflight → health → doctor → inodes → topic → lock → watchdog) →
  sweeper/watchdog/doctor references
  (`OPERATIONS.md:2086-2346`; mirrors `scripts/README.md`,
  `stellereum/scripts/four-node/FAULT_RUNBOOK.md:196-258`).
- Incident runbooks with abort criteria: 4-validator fault injection
  (prepared, NOT executed — `FAULT_RUNBOOK.md:1-8`), monitor RUNBOOK per
  alert (`monitor/RUNBOOK.md`), restart-vs-wipe-vs-escalate ladders.

---

## 8. What is MISSING for professional ops — ranked by risk

> Rank = likelihood × blast radius for a 3-node testnet. Note the quorum
> math first: **N=3 needs 3/3** (`OPERATIONS.md:430-480`) — any single
> validator down **stalls** the chain. Everything below is worse because of
> that.

1. **No scheduled, off-host, verified backups — single-disk loss = history loss.**
   Exists: manual `backup.sh`/`restore.sh` + verification-at-write (§4).
   Missing: timer/cron ownership, off-host encrypted copies, freshness alert,
   restore drill, C/third-node coverage. Nearest risk: hot tarballs, same-disk
   retention, plaintext-if-copied. Action: define `BACKUP_DIR` off-host,
   `--keep`, owner; schedule per node; alert on age; rehearse `restore.sh` on
   a spare dir; extend coverage to the third node.

2. **3-node quorum is fragile by construction — no maintenance story.**
   Exists: N=4-survives-1 analysis, coordinated-rotation procedure.
   Missing: any documented way to do planned work (deploy, prune catch-up,
   host patch) on a 3-node set without stalling; no 4th-validator or
   observer-promotion plan; `STELL_NODES="A B C"` + expected values for the
   testnet are not checked in. Action: either accept stall-during-maintenance
   explicitly (with comms), or add a 4th validator / documented rotation
   window; check in the 3-node `STELL_CONF`.

3. **Fast-sync depends on an unattributed snapshot feed.**
   Exists: consumer URL + `meta.json` check in `stell-sync.sh`.
   Missing: publisher, cadence, signing/freshness SLO (see §4). If
   `latest.tar.zst` is stale or compromised, every `sync`/`auto-heal` and
   every new observer inherits it. Action: name the publisher + cadence;
   gate `sync` on `meta.json` height/freshness; document the fallback
   (protocol bootstrap via `node-bootstrap` instead of HTTP).

4. **Log retention + alert delivery are not wired end-to-end.**
   Exists: rules, `check.sh`, runbooks, rotation knobs (§5).
   Missing: journal caps/forwarding, stderr shipping (persist-queue drops),
   Alertmanager receivers, dashboards, inode-rate and backup-freshness pages,
   per-node port split confirmation. All alerting claims are **UNVERIFIED**
   until something actually pages. Action: ship journald drop-in + forwarder,
   wire receivers, split explorer ports per node, add the two missing alerts
   (inodes, backup age), stand up one height-rate dashboard.

5. **No upgrade / rollback rehearsal and no key-compromise runbook.**
   Exists: exit-42 + staging rules + rollback text; Falcon rotation text.
   Missing: rehearsed upgrade (stage → propose → halt-42 → restart → verify
   roots/tips), pinned `*.prev-<version>` binaries + pre-upgrade backups as a
   standing habit, Ed25519 rotation / passphrase-loss / suspected-leak
   procedures and their quorum implications. Action: rehearse on the
   3-node set (or local-cluster) before the first governed upgrade; write the
   identity-key rotation order explicitly.

Lower but real: retention triad disagreement (`STELL_KEEP_BLOCKS` 8000 conf
vs 50000 code vs 1000000 docs; `STELL_MIN_BLOCK_MS` 50 conf vs 400 live;
inode warn/hard 70/85 conf vs 80/90 docs) — pick testnet values and pin them
in the checked-in conf; no RTO/RPO statement; no firewall/TLS inventory
beyond loopback defaults + `allow-unknown`/`unknown-allow` notes; no chaos
expectation for N=3 beyond local-cluster's honest "kill stalls finality".

---

## 9. Restart procedures (one node / all nodes)

> These are procedures, not an executed drill. Unit names and scopes come from
> `scripts/cluster-nodes.conf`: A/C/D are `system` units, B is a
> `systemctl --user` unit. Adjust `STELL_NODES` for the 3-node set. Nothing
> in this section authorises a restart without the human order required by
> AGENTS.md §6.

### 9.0 Rules that apply to every restart

1. **Read-only check first and last.** `scripts/cluster_liveness.sh` is the
   entry and exit gate for every restart:
   ```bash
   STELL_RPCS="A=http://127.0.0.1:8545,B=http://127.0.0.1:8546"
   scripts/cluster_liveness.sh --rpcs "$STELL_RPCS" --window 90
   ```
   Capture heights, spread, verdict and the `LIVENESS_RESULT=` line. The
   later blocks use `$STELL_RPCS`; `export` it if they run in a new shell.
2. **Quorum math first.** N=4 survives one validator down; N=3 needs **3/3**
   and any single restart stalls finality. For N=3 the restart needs an
   explicit window and comms, not just an operator at a keyboard.
3. **Observed failure modes.** The live cluster has shown both:
   - **height split** — `cluster_liveness.sh` reports `spread > 1`; one
     validator is behind and may or may not be catching up. A lagging node
     alone is *not* a reason to wipe.
   - **round split** — heights can be close while `/health` shows
     `consensus.round` / `last_finalized_round` far apart, rounds advancing
     independently and no QC forming. This is the failure documented in
     `docs/LIVENESS_ROUND_SYNC_AUDIT.md`; a single restart may or may not
     re-converge, and a coordinated restart may be required.
4. **Do not wipe data unless the genesis/fork id changed.** Before any
   destructive step compare identity across nodes:
   ```bash
   for u in 8545 8546 8547 8548; do
     curl -s "http://127.0.0.1:$u/health" \
       | jq -c '{chain_id:.identity.chain_id,fork_id:.identity.fork_id,
                 height:.chain.height.value,round:.consensus.round.value}'
   done
   ```
   If `chain_id`/`fork_id` agree across nodes and with
   `EXPECT_STELL_CHAIN_ID=5757`, a wipe destroys recoverable state and is not
   justified. If they differ, stop and escalate (genesis discipline: §3;
   `docs/FRESH_GENESIS_RUNBOOK.md`). Never delete single store files as a
   "fix".
5. **Stop/start, never `kill -9`.** A mid-write kill risks the sled store and
   the consensus checkpoint. `Restart=always` is already trying; a manual
   systemd restart is the supported path.

### 9.1 Restart one node

Example for node B (local `--user` unit); for A/C/D use
`systemctl restart stell-node<X>.service` on the host from
`scripts/cluster-nodes.conf`:

```bash
# 1. Pre-check (read-only) and save the output to the incident log.
scripts/cluster_liveness.sh --rpcs "$STELL_RPCS" --window 90

# 2. Stop one node by its unit; wait for the unit to become inactive.
systemctl --user stop stell-nodeB.service
systemctl --user is-active stell-nodeB.service       # expect: inactive/failed

# 3. Start the same unit. Do not edit/delete env, keys or data.
systemctl --user start stell-nodeB.service
journalctl --user -u stell-nodeB.service -f           # watch for FINALIZED/catch-up

# 4. Post-check after it is reachable again (give catch-up time).
scripts/cluster_liveness.sh --rpcs "$STELL_RPCS" --window 90
```

Acceptance: verdict `OK`, `spread <= 1`, block hashes agree at the common
height, and every reachable height advances for at least two minutes. A
briefly larger spread while the restarted node catches up is expected; a
spread that is *growing*, a regressed height, or `DIVERGED` is not.

If the node does not catch up: collect `journalctl`, `df -i`, disk and
`scripts/doctor.sh` output; verify chain/fork identity (9.0.4) and the env
file; check for a stale lock with `scripts/stell-sync.sh lockclear <node>`
(plan mode first — it stops the node). Do not wipe, and do not restore a
backup over live data unless a human has confirmed the genesis/fork change.

**Round split case:** if heights look fine but `/health` rounds stay far
apart and finality is not advancing, restart the node whose round is
furthest from the others *only after* recording every node's
`round`/`last_finalized_round`. Re-check after it rejoins. If the split
persists, stop and escalate; this is not fixed by deleting data.

### 9.2 Restart all nodes

Only with an explicit human order that names the window. Expect finality to
stop during the last restart on N=3, and for the duration of a simultaneous
restart on N=4.

There are two supported shapes:

**A. Controlled sequence (preferred for recovery).** Start the reference node
first, then one node at a time, checking quorum between steps:

```bash
# Freeze load generators / writers first; record the pre-restart liveness line.
scripts/cluster_liveness.sh --rpcs "$STELL_RPCS" --window 90 | tee pre-restart.log

# Topology is read-only; use its host/scope values instead of hard-coding.
. scripts/cluster-nodes.conf

# Node A (reference, system unit on its host)
ssh $NODE_A_SSH_OPTS "$NODE_A_SSH" 'systemctl restart stell-nodeA.service'
scripts/cluster_liveness.sh --rpcs "$STELL_RPCS" --window 90

# Node B, then C, then D: one at a time, same stop/start pair.
systemctl --user restart stell-nodeB.service
ssh $NODE_C_SSH_OPTS "$NODE_C_SSH" 'systemctl restart stell-nodeC.service'
ssh $NODE_D_SSH_OPTS "$NODE_D_SSH" 'systemctl restart stell-nodeD.service'

# Final gate: OK, spread <= 1, hashes agree, heights advance for 2 minutes.
scripts/cluster_liveness.sh --rpcs "$STELL_RPCS" --window 90 | tee post-restart.log
```

With N=4, stop/start each node while the other three keep quorum; do not run
the three remote restarts in parallel unless the order explicitly allows a
full-cluster outage.

**B. Parallel restart via the shipped tool.** `scripts/stell-sync.sh restart`
restarts every node's service concurrently. It is the fastest path and the
largest blast radius; use it only when the order says a whole-cluster outage
is acceptable:

```bash
scripts/stell-sync.sh restart
```

After either shape: confirm all four heights advance, `cluster_liveness.sh`
returns `OK`, `/health` verdicts are healthy/ready, and no node logs
`rejected proposal` / fork / divergence lines. If a node fails to start,
leave its data in place, capture the journal and escalate — **do not wipe**.

### 9.3 What a restart does not fix

- **Genesis/fork-id mismatch:** a restart loops the same mismatch. Compare
  identity and escalate; only a coordinated genesis change justifies new
  data directories.
- **Corrupt or full disk / inodes:** fix the host (space, inodes) before
  restarting; repeated restarts can deepen the problem.
- **Round split caused by software divergence:** if all nodes restart and
  the round split returns immediately, preserve logs and escalate to the
  binary/ruleset owner; do not "fix" quorum or wipe state.
