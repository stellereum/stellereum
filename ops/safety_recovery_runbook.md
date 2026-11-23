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
