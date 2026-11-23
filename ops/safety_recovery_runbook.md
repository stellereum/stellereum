# Safety quarantine — recovery runbook

Applies to: `nodeC` incident, 2026-11-23. Symptom, cause, and the exact
recovery procedure, so the next operator does not have to rediscover it.

## Symptom

The node starts, syncs, finalizes — but logs, once, at startup:

```
ERROR stellereum::safety: [safety] QUARANTINED (fail-closed Observer):
failed to open safety_record_v1: safety store requires recovery
```

It is alive and serving RPC, but it **does not vote**. If it is in the active
set, the cluster believes it is a validator while it contributes nothing.

## Why it is fail-closed (and this is correct)

`SafetyRecordStore` latches an in-process `failed` flag on the first failed
read/decode and from then on refuses every `load`/`persist` with "requires
recovery". A validator that cannot prove it has not already voted at a height
must not sign. The node therefore degrades to Observer instead of risking a
double vote. This behaviour is intended; only the recovery path was missing.

## Known causes

1. **Two processes on one data directory** (the incident). The
   `stell-node-guard.timer` restarts a stopped unit within 60 s, so any
   stop/start that is not guarded can overlap: `systemctl restart` brings the
   node down, the guard sees it down and starts a second instance, and both
   hold the same sled store. sled's lock is not used by the node to refuse
   startup, so the second instance corrupts the first record read.
   `scripts/rolling-deploy.sh` now pauses the guard around the restart for this
   reason; do the same by hand.
2. Genuine store corruption (power loss, full disk, inode exhaustion).
3. Identity change (validator key replaced) — decode checks
   `(validator, chain, shard)`.

Diagnose before acting: the **old and new binaries must fail identically**;
if only the new binary fails, it is a release regression, not a store problem.

## Recovery procedure (offline, ~2 minutes)

Run on the node, as root, from the node directory. The node must be stopped and
**no process may hold the store**.

```sh
cd /root/nodeC

# 1. Stop and make sure NOTHING is left (Restart=always will fight you).
systemctl stop stell-nodeC
systemctl mask --runtime stell-nodeC
for i in $(seq 1 30); do pgrep -f 'nodeC/steller[e]um run' >/dev/null || break; sleep 2; done
pgrep -af 'nodeC/steller[e]um run' || echo "no process"

# 2. Delete the undecodable record (requires explicit fencing confirmation).
./stellereum safety-reset --store-dir ./data/store --i-fenced-all-signers

# 3. Write generation 1 from the current finalized head.
./stellereum safety-init --store-dir ./data/store --keys-dir ./keys \
    --shard 0 --i-fenced-all-signers

# 4. Bring the node back.
systemctl unmask stell-nodeC
systemctl start stell-nodeC
```

Verify: no `QUARANTINED` line after startup, the process is a single PID, and
`stell_getValidatorStatus` shows the validator voting again once it is in the
active set.

`safety-init` refuses to run while a record still exists, and refuses floors
below the legacy watermark, so a second invocation cannot silently destroy a
healthy record.

## Recovering a node that cannot catch up (stuck behind)

Symptom: the node keeps logging `[sync] REFUSING snapshot at <h>: trailing header
proof failed: ...` and `view change -> height <H> round <r>` without advancing.
Two known refusals (`P0-PEER-SNAPSHOT-ANCHOR` in `docs/OPEN_DEFECTS.md`): the
anchor header at the snapshot boundary is not published, or the historical
validator set used for the proposer check does not match the set in force at
that height. Both refusals are correct; the missing piece is a recovery path.

Workaround — restore from the PUBLIC HTTP snapshot (this is a supported path,
`scripts/join-testnet.sh` uses the same URL):

```sh
cd /root/nodeC
systemctl stop stell-node-guard.timer
systemctl mask --runtime stell-nodeC
systemctl stop stell-nodeC
for i in $(seq 1 45); do pgrep -f 'nodeC/steller[e]um run' >/dev/null || break; sleep 2; done
pgrep -af 'nodeC/steller[e]um run' || echo "no process"

mv data data.bak-stuck-$(date +%s)
mkdir -p data
curl -fsSL https://rpc.stellereum.org/snapshot/latest.tar.zst | tar -I 'zstd -d' -xf - -C data/

# The snapshot carries the PRODUCER's safety record: clear it, initialise ours.
set -a; . ./env.C; set +a
./stellereum safety-reset --store-dir ./data/store --i-fenced-all-signers
./stellereum safety-init --store-dir ./data/store --keys-dir ./keys --shard 0 --i-fenced-all-signers

systemctl unmask stell-nodeC
systemctl start stell-nodeC
systemctl start stell-node-guard.timer
```

Keys and `env.*` are never touched. The old data directory can be deleted once
the node is at tip; leaving it costs inodes (that is what put nodeC at 100 %).

## Disk full / disk pressure

The 9.8 GB validator disks fill from three independent directions; check all
three, because each has a different fix.

| Source | Symptom | Fix |
|---|---|---|
| `safety`/store growth | `data/` grows every block | prune mode: `STELL_ARCHIVE=0` + `STELL_KEEP_BLOCKS=50000` (stops growth; sled does NOT return the freed file space to the OS, so it does not shrink an already-large store) |
| `/var/log/syslog` duplication | one node had **2.4 GB** in `syslog`+`syslog.1` while another had 17 MB | `: > /var/log/syslog`, `: > /var/log/syslog.1`, plus `/etc/logrotate.d/stell-node` with `maxsize 200M / rotate 2 / compress` |
| inodes | `df -i` at 100 %, writes fail, `safety_record_v1` corrupts | delete stale `data.bak-*` trees (one was 302 k files) and keep `scripts/node-prune-cron.sh` installed |

Two more space consumers seen on validators: `~/.rustup` + `~/.cargo` (about
935 MB, only needed on a build host) and old `data.bak-*` directories (1.4 GB).
Neither is needed on a running validator.

### The inode arithmetic that keeps biting (chunk store)

The DHT blob store writes **one file per chunk**: about **7 files per block** at
the live block size, so ~1 300 files/minute at 176 blocks/min. The sweeper only
deletes chunks older than its grace period, so the steady state is
`grace_minutes × 1 300` files plus the referenced ones:

| grace | steady-state chunk files | + referenced (~73 k) | of 655 360 inodes |
|---|---|---|---|
| 6 h (old default) | ~468 k | ~541 k | **83 %** — no headroom |
| **2 h (current)** | ~156 k | ~229 k | **35 %** |

`kv.json` is debounced at 30 min (`INFNODE_KV_DEBOUNCE_MS=1800000`), so a 2 h
grace still leaves a 4× safety margin against deleting a chunk that is not yet
referenced. The cron/timer passes `--grace-seconds 7200` on every node
(`/etc/cron.d`-style cron on A/C/D, a systemd user timer on the B host).
Watch `df -i`, not just `df -h`: nodeC reached 100 % inodes with 1.5 GB of disk
still free, and that read-only state is what corrupted its safety record.

To actually SHRINK a store that is already large, restore the public snapshot
into a fresh `data/` (see the recovery section above) — that took nodeB from
1.6 GB to 173 MB and nodeC from 1.5 GB to a fresh store.

## Rules that prevent a repeat

0. **Pause the liveness guard** (`systemctl stop stell-node-guard.timer`) before
   any stop/start, and resume it afterwards. It fires within 60 s and will
   happily create the second instance that corrupts the store.
1. **Never start a second instance** on the same data directory. Before
   `systemctl start`, confirm `pgrep -f '<node>/steller[e]um run'` is empty.
2. `pkill -f '<pattern>'` matches the invoking shell's own command line when the
   pattern appears in it — use `'steller[e]um'` and kill by PID.
3. The unit's `TimeoutStopSec` is 90 s and a busy node can use all of it. A
   deploy that gives the restart 30 s will report a false failure while the node
   is still draining.
4. Inode exhaustion (`df -i` at 100%) makes writes fail and can corrupt the
   store: keep the prune cron installed on every node (see
   `scripts/node-prune-cron.sh`) and alert at 80% for both `df -h` and `df -i`.

## Still missing (tracked in the wave plan)

- A **data-directory file lock** so a second instance fails fast instead of
  corrupting the store (Wave 2).
- Automatic detection of "in active set but Observer" as a first-class alert
  (`validator_efficiency`, Wave 1).
