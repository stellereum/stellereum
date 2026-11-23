---
title: Node operations
description: systemd hardening, retention, pruning, stelops, backup/restore and incident runbooks.
outline: deep
---

# Node operations

Node operations is the part of the runbook that keeps a node alive after it has synced: disk and inode pressure, log retention, the persist queue, backup and restore, and the tools for a stale lock or a divergent store. Use it when a node is unhealthy, and rehearse the backup path before you need it.

::: danger A 1-vCPU box is not a validator
The project measured 1 vCPU / 3.8 GB hosts live and recorded scheduler
starvation (>63 % sys / 36 % iowait, load ~4), 0.35–2 s transport RTT dominating
consensus, and four consensus loops on one core costing ~25 % throughput. The
in-tree systemd units are hardened for that small testnet host, but the
**minimum validator is 4 vCPU / 8 GB / 100 GB SSD**. Use the 1-vCPU guidance
below only for an observer or a lab.
:::

## Sizing

| Role | vCPU | RAM | Disk |
| --- | --- | --- | --- |
| validator | ≥ 4 | ≥ 8 GB | ≥ 100 GB SSD, < 80 % used |
| observer | ≥ 2 | ≥ 4 GB | ≥ 60 GB SSD |

The node process is capped at `MemoryMax=2G` in the shipped units; the host
needs headroom for sled flush, snapshots and snapshot-sync replay. Spinning
disk stalls the persist queue and reads as consensus lag.

## systemd unit

The shipped units (`stellereum/scripts/systemd/stell-nodeA.service`) are a good
baseline:

```ini
[Unit]
Description=Stellereum node A
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/nodeA
EnvironmentFile=/root/env.A
ExecStart=/root/stellereum/stellereum run --config node.yaml --shard 1
Restart=always
RestartSec=5
MemoryMax=2G
CPUQuota=80%
Nice=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=stell-nodeA
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Why each line exists:

| Directive | Reason |
| --- | --- |
| `StartLimitIntervalSec=300` + `StartLimitBurst=5` | Stop a structural crash loop instead of melting the disk and journal. Investigate with `journalctl`, then `systemctl reset-failed`. |
| `Restart=always` + `RestartSec=5` | Survive crashes/ssh drops; 5 s lets the sled lock and ports release. |
| `MemoryMax=2G` | Cap, not reservation. Stops a runaway node from OOM-killing a sibling on a small box. |
| `CPUQuota=80%` | Keeps sshd and journald responsive on 1 vCPU. Raise to 100–200 % on a multi-core host. |
| `Nice=5` | Deprioritizes the node slightly under host contention. |
| `StandardOutput=journal` / `StandardError=journal` | Avoids the ever-growing `run.log` / `current.log`. |
| `PrivateTmp=true` | Cheap isolation that cannot break a node using only `./data` and `./keys`. |
| `EnvironmentFile` with **no** leading `-` | A missing env file must fail the unit, not start with wrong ports or no auth token. |

### Optional hardening

Add only after testing on your host:

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/root/nodeA
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
```

`ProtectSystem=strict` makes the whole filesystem read-only except
`ReadWritePaths`; the node needs write access to its data dir, keys dir and
upgrade staging dir. A missing `ReadWritePaths` looks like `Permission denied`
on the sled store.

::: warning Do not use `Restart=always` with exit 42
For an upgrade-aware unit, use either `--supervise` (the upgrader owns the
child) or `RestartPreventExitStatus=42`. With plain `Restart=always`, exit 42
restarts the **old** binary in a loop. See [Upgrades](/nodes/upgrades).
:::

## Logs: journald and logrotate

`StandardOutput=journal` sends node output to journald. Bound it:

```ini
# /etc/systemd/journald.conf.d/stellereum.conf
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
RateLimitIntervalSec=30s
RateLimitBurst=1000
```

```bash
systemctl restart systemd-journald
journalctl --disk-usage
journalctl -u stell-nodeA --since "1 hour ago"
```

If you still write plain log files (older deployments, wrappers), rotate them:

```text
# /etc/logrotate.d/stellereum
/root/node*/run.log /root/node*/current.log /root/node*/live.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
```

Node output on **stderr** matters. Some critical lines bypass `tracing`:

```text
[storage] persist queue full; dropping a job (disk too slow?)
[storage] persist error: …
[rpc] server error: …
```

A deployment that ships only structured logs will miss them. Capture stderr.

## Retention and pruning

The default is **archive**: every block body is kept forever. That is
deliberate — dropping a body is irreversible and removes re-execution.

| Variable | Value | Effect |
| --- | --- | --- |
| `STELL_ARCHIVE` | unset / `1` / anything not `0`/`false` | archive (default), unbounded |
| `STELL_ARCHIVE` | `0` / `false` | prune bodies older than `height - STELL_KEEP_BLOCKS` |
| `STELL_KEEP_BLOCKS` | default `50000` | only consulted in prune mode |
| `STELL_SNAPSHOT_INTERVAL` | default `1000`, minimum `50` | state/domain snapshot cadence |

A public-testnet starting point:

```bash
STELL_ARCHIVE=0
STELL_KEEP_BLOCKS=1000000
```

Set the **same values on every node**. Retention is node-local and not part of
the state root, so a mismatch does not split the chain, but it changes what
history a node can serve.

Pruning is not free or immediate: a pass rides the snapshot cadence and removes
at most `PRUNE_BATCH = 20,000` bodies. A store far behind the boundary keeps
growing for a while after you enable pruning.

::: tip Snapshot cadence and the 256-block walk cap
After a snapshot restore at height `B`, a node refuses a body walk longer than
**256** blocks. Consecutive snapshots can be up to `snap_int + 100 = 1100`
blocks apart. On a live chain this is a bounded wait; on a **halted** chain the
next snapshot never comes. Setting `STELL_SNAPSHOT_INTERVAL ≤ 156` on every
node makes `interval + 100 ≤ 256`, so the walk can always close the gap. This
is a node-local setting, not consensus.
:::

## Inode and disk guards

The incident that wrote this section: one node accumulated **463,589 orphan
chunk files**, consumed all **655,360 inodes** (`df -i` = 100 %), went
read-only and **silently dropped out of consensus** while answering RPC
normally. A sibling with the prune timer never saw it.

The number that matters is **inodes**:

```bash
df -i ./data      # warn ≥ 80 %, critical ≥ 90 %
df -h ./data      # bytes are the second signal
du -sh ./data/store
```

Install the sweeper as a **timer on every node**:

```bash
# dry run first
scripts/node-prune-cron.sh --dir /root/nodeC --dry-run

# real run
scripts/node-prune-cron.sh --dir /root/nodeC

# systemd
cp scripts/systemd/stell-node-prune.service /etc/systemd/system/
cp scripts/systemd/stell-node-prune.timer   /etc/systemd/system/
# edit WorkingDirectory/ExecStart to THIS node's directory
systemctl daemon-reload
systemctl enable --now stell-node-prune.timer
```

How it decides what is garbage:

1. referenced set = every chunk id mentioned by any manifest in
   `<data>/kv.json` (conservative: expired manifests count as referenced);
2. candidate = a chunk file not in that set **and** older than the grace period
   (6 h default, because `kv.json` is debounced);
3. the candidate list is re-verified immediately before deletion;
4. deletion is batched and capped (`--max-delete`, default 200,000).

It refuses to run when `kv.json` is older than `--max-kv-age` (2 h). It never
touches the head pointer's chunks, the active snapshot's chunks, the store, the
keys or the config.

There is **no disk metric** in `/metrics`: `sled 0.34` has no per-tree
`size_on_disk`. Alert on growth rate, not a threshold. In archive mode the
correct alert is "growing at all, faster than your disk".

## The persist queue

Finalized blocks, headers, checkpoints and snapshots go through a bounded
background queue (`PERSIST_QUEUE_CAP = 8192`). It never blocks consensus. If the
disk cannot keep up, jobs are **dropped**:

```text
[storage] persist queue full; dropping a job (disk too slow?)
```

That means on-disk state is behind memory. Treat it as a disk-performance
incident, not a consensus incident.

## Preflight

Before **every** deploy:

```bash
scripts/stell-sync.sh preflight || { echo "REFUSING TO DEPLOY" >&2; exit 1; }
```

It compares nodes against each other and against `scripts/cluster-nodes.conf`:

- reachability (ssh/RPC);
- pubsub topic and `STELL_SHARDS`;
- chain id and genesis root;
- `STELL_MIN_BLOCK_MS`, `STELL_DOWN_PROPOSER_TIMEOUT_MS`, `STELL_KEEP_BLOCKS`,
  admission base fee;
- inode usage;
- a binary inside a cargo target dir (the `cargo clean` hazard);
- unit enabled + active.

If preflight fails, fix the config and re-run. Do not deploy.

## `stelops`

`scripts/tools/stelops` reads the store offline (build it once; it depends on
sled only):

```bash
cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml
```

| Command | Purpose |
| --- | --- |
| `stelops checkpoint <store-dir>` | print the consensus checkpoint (height, round, locked hash/round, finalized height) |
| `stelops genesis-root <store-dir>` | print the genesis root (= chain epoch = topic) |
| `stelops doctor <store-dir> [--shards 0,1] [--json]` | full diagnosis: genesis root, epoch, shards, topics, checkpoint, finalized pointer |
| `stelops diverge <data-dir-A> <data-dir-B> [--shards 0,1]` | offline fork diff; exit 1 on any difference |
| `stelops clear-lock <store-dir> --force` | remove a stale consensus lock |

::: danger The node must be stopped
sled holds an **exclusive** lock on the store while the node runs. `checkpoint`,
`doctor`, `diverge` and `clear-lock` all need the process stopped. `clear-lock`
is the only mutating command and refuses without `--force`.
:::

### Stale consensus lock

The consensus safety state (height, round, locked hash) lives under the meta key
`consensus`. On restart the node restores it, and the rule is "never adopt a
peer's round". A node that resumes at round 56 while peers are at round 0 can
never rejoin.

```bash
# plan only — does not touch the node
scripts/stell-sync.sh lockclear C

# stop, verify, clear, start
scripts/stell-sync.sh lockclear C --force
```

The tool refuses when the lock is **not ahead** of the peers' tip (a lock that
is behind is not the cause), never touches the finalized pointer, and backs the
removed bytes up as `consensus-checkpoint.bak.<ts>` next to the store.

Direct form:

```bash
scripts/tools/stelops/target/release/stelops checkpoint /root/nodeC/data/store
scripts/tools/stelops/target/release/stelops clear-lock /root/nodeC/data/store --force
```

### Divergence

```bash
scripts/tools/stelops/target/release/stelops diverge \
  /root/nodeA/data /root/nodeB/data --shards 0,1
```

It compares genesis root, epoch, per-shard finalized height/hash, checkpoint
height and snapshot heights. Exit 1 on any difference. A same-finalized-hash
pair with different state snapshots at the same height is reported as an
execution divergence the finalized hash alone cannot see.

## Backup and restore

Two non-equivalent backup systems exist in the tree:

- `scripts/backup_verify.sh` + `scripts/backup_offhost.sh` +
  `scripts/backup_restore_drill.sh` — 3-2-1, encrypted, manifest-checked;
  **keys are inventory-only, never copied**;
- `stellereum/scripts/backup/backup.sh` + `restore.sh` — tarball includes
  `node.yaml`, `data/` and **`keys/`**.

For **host loss**, the second is what you need: a lost `validator.key` is
unrecoverable identity. Keep an encrypted keys archive under the same 3-2-1
policy.

### What is in the tarball

| Member | Why |
| --- | --- |
| `nodeA/node.yaml` | peer set, listen/advertise — defines the chain |
| `nodeA/data/` | store, `kv.json`, `mail.key`, `mempool.bin` |
| `nodeA/keys/` | `identity.key`, `e2e.key`, `falcon.key`, `withdrawal.key` |
| `env.A` | `STELL_RPC_LISTEN`, tokens, passphrase |

Tarballs are mode `600`. Treat them as secrets; never commit them.

### Back up

```bash
# trustworthy: stop first (a hot tarball can catch sled mid-write)
systemctl stop stell-nodeA
stellereum/scripts/backup/backup.sh --node A
systemctl start stell-nodeA

# both nodes, keep 7 each
stellereum/scripts/backup/backup.sh

# custom destination/retention
stellereum/scripts/backup/backup.sh --node A --dir /root/backups --keep 14
```

Each tarball is verified (`tar -tzf`, four members present) before retention
pruning.

### Restore

```bash
# restore.sh stops the unit, checks /proc for stragglers, snapshots current
# state to pre-restore-nodeA-<ts>.tar.gz, and does NOT start the node
stellereum/scripts/backup/restore.sh /root/backups/stell-nodeA-20260926T120000Z.tar.gz A

# sanity
tar -tzf /root/backups/stell-nodeA-20260926T120000Z.tar.gz | head
diff <(tar -xzOf /root/backups/stell-nodeA-20260926T120000Z.tar.gz nodeA/node.yaml) \
     /root/nodeA/node.yaml

# start by hand
systemctl start stell-nodeA
journalctl -u stell-nodeA -f
```

If it exits with `genesis state root mismatch`, the backup predates a genesis
change (validator set, balances, faucet key). That refusal is the safety net.
Restore a post-change backup, or wipe **every** node's `./data` for a new
chain.

::: danger Never delete a single file to "fix" anything
Never delete `data/store`, `data/kv.json` or `data/mail.key` individually — not
to free disk, not to clear a faucet nonce gap, not to clear a genesis mismatch.
A single deleted file is a torn identity: the node refuses to start or starts a
private chain. A wipe is **whole `./data` on every node at the same moment**.
:::

## Failure-mode runbook

| Symptom | Diagnosis | Fix |
| --- | --- | --- |
| node "up", RPC fine, out of consensus; `df -i` 100 % | `df -i ./data`; orphan count | `node-prune-cron.sh --dir <dir>`; install the timer everywhere |
| validator isolated, zero log evidence (`STELL_SHARDS` regressed) | `stell-sync.sh topic <node>`; `preflight` | fix env to match cluster; restart (config error, never auto-heal) |
| node up, right topic, never finalizes | `doctor`; `stelops checkpoint` (stopped) | `lockclear <node> --force` |
| `203/EXEC` crash loop | binary was in a cargo target dir and `cargo clean` removed it | move binary out, repoint `ExecStart`, restart |
| same height, different `stell_getStateRoot` | fork / split | find the config divergence; do not wipe blindly |
| `Could not acquire lock` | old process or stale lock | kill, wait ~20 s, verify `pgrep`, restart |
| `genesis state root mismatch` | changed validators/faucet/binary | restore original config; coordinated wipe only |
| faucet drips stuck `pending` | faucet nonce gap after mempool wipe | clamp is automatic on restart; fund the faucet's own shard |
| `persist queue full` | disk too slow | move to SSD; check `iostat`; reduce write pressure |
| node restarts every 5 s | crash loop / bad config | `journalctl -u … -n 200`; `systemctl reset-failed` after fixing |

::: danger A restart longer than the jail budget jails the validator
`DOWNTIME_MISS_THRESHOLD = 42` misses is `42 × STELL_MIN_BLOCK_MS`: **33.6 s at
the live 800 ms tempo** (16.8 s at 400 ms). A restart that keeps the validator
silent longer than that is a 0.1 % slash plus a ~53-minute jail that only the
cold withdrawal key can clear. Pre-stage the binary and use the
[live rolling deploy](/nodes/upgrades#live-rolling-deploy).
:::

## Watchdog

```bash
scripts/cluster-watchdog.sh --interval 60 [--once] [--no-heal]
```

| Condition | Auto-heal | Action |
| --- | --- | --- |
| service down/failed | yes | `systemctl restart` |
| inode usage at hard threshold | yes | run the orphan sweeper |
| many orphan chunks | yes | run the sweeper |
| different topic | no | report only — config error |
| config drift | no | report only |
| tip not advancing | no | report only — a view-change storm needs a human |
| stale lock | no | report only — `lockclear --force` |
| node behind | no | report only — re-sync is an operator decision |

For a single-host deployment, `stall_watchdog.sh` restarts via `stell-node.sh`
after 180 s of flat heights.

### Per-node guard: restart the dead, never the stalled

`scripts/stell-node-guard.sh` is the minimal systemd-timer guard installed on
each host (60 s cadence):

```bash
STELL_GUARD_UNIT=stell-nodeA \
STELL_GUARD_RPC=http://127.0.0.1:8545 \
STELL_GUARD_STATE_DIR=/var/lib/stell-node-guard \
STELL_GUARD_VALIDATOR=<validator-id> \
  scripts/stell-node-guard.sh --once
```

`STELL_GUARD_UNIT` (singular) is accepted as an alias of the default
`STELL_GUARD_UNITS` scan; `STELL_GUARD_SCOPE=user` targets a `systemctl --user`
unit (as on a non-root operator box).

| Situation | Action |
| --- | --- |
| unit not `active`/`activating`/`reloading` | restart (max 5 per hour) |
| unit alive, height flat | **log only** — a cluster-wide halt must not become a synchronized restart storm |
| `STELL_GUARD_VALIDATOR` set, validator jailed and `height >= release_height` | **alert** once per 10 min; never auto-unjail (that needs the cold key) |
| `STELL_GUARD_VALIDATOR` set, `withdrawal_address = null` | one-time alert: the validator is unmanageable until `claim-withdrawal` |

The guard never touches keys, the store, the consensus lock or the config.

## Next

Continue with [Monitoring](/nodes/monitoring) to turn these failure modes into alerts, and [Upgrades](/nodes/upgrades) for the height-triggered binary swap.
