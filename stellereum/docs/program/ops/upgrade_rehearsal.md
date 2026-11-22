# Binary-upgrade rehearsal drill

Rehearse a node binary swap on a throwaway/local cluster BEFORE touching any
live node. Goal: prove the new binary boots on real (copied) state, catches
up, and finalizes — and prove you can roll back.

Conventions used below (all verified in-repo 2026-11-02):
- Binary candidates (cf. `resolve_bin` in `scripts/local-cluster.sh`):
  `stellereum/target/{debug,release}/stellereum`, `target/{debug,release}/stellereum`, or `which stellereum`.
- Node start shape: `<bin> run --config node.yaml --shard 0` (data dir `./data`
  by default; `NodeBootstrap --data-dir` only for the fresh-observer path).
- Local-cluster layout: `run/cluster/node<i>/{node.yaml,env.<i>,node.pid,live.log,data/}`;
  ports RPC `127.0.0.1:18645+i`, explorer `127.0.0.1:18080+i`, P2P `127.0.0.1:19410+i`.
  Single-node defaults: RPC `127.0.0.1:8545`, explorer `127.0.0.1:8080`.
- Cluster commands: `./scripts/local-cluster.sh up [N] | status | stop [i] | start <i> | restart <i> | down | reset | chaos`.

## 0. Record the baseline (old binary still running)

```bash
NODE=1
RPC=http://127.0.0.1:$((18645 + NODE))
EXP=http://127.0.0.1:$((18080 + NODE))

# Build identity + live height, three ways (must agree):
curl -s $EXP/api/version
curl -s $EXP/metrics | grep -E '^stell_(consensus_height|consensus_round|build_info)'
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' $RPC

./scripts/local-cluster.sh status
grep -c 'FINALIZED block #' run/cluster/node$NODE/live.log
```

Note the old version string from `/api/version` — you will compare after the swap.

## 1. Build the candidate binary

```bash
cargo build --release -p stellereum
NEW_BIN=$PWD/target/release/stellereum
$NEW_BIN --version   # sanity: it executes
```

## 2. Snapshot the node's data dir (non-destructive, read-only on live)

```bash
# Dry-run first to see the plan:
scripts/backup_verify.sh --data-dir run/cluster/node$NODE/data --dry-run

# Real verification (stop the node first for a strict image):
./scripts/local-cluster.sh stop $NODE
scripts/backup_verify.sh --data-dir run/cluster/node$NODE/data \
  --work-dir /tmp/opencode/stell-upgrade-node$NODE
# Expect: PASS: backup verified: <N> files, manifest match, boot-read OK
```

The live dir is only ever copied (`cp -a`); the manifest lives in the work
dir. Keep `/tmp/opencode/stell-upgrade-node$NODE/snapshot` — it is your
rollback image.

## 3. Swap the binary and boot

Local-cluster path (rolling, one node at a time):

```bash
# Make the cluster boot the candidate. `start`/`restart` use `resolve_bin`,
# which picks the first executable of:
#   stellereum/target/debug/stellereum, stellereum/target/release/stellereum,
#   target/debug/stellereum, target/release/stellereum, `which stellereum`.
# So either `cargo build --release -p stellereum` in place (it overwrites the
# candidate the old node used — snapshot first, step 2), or back up the old
# file and copy the candidate over it:
#   cp "$(ls stellereum/target/release/stellereum target/release/stellereum 2>/dev/null | head -1)" /tmp/opencode/stellereum.old
./scripts/local-cluster.sh start $NODE   # or: restart $NODE (stop+boot in one)
sleep 10
tail -20 run/cluster/node$NODE/live.log
```

Single-node path (same idea without the cluster script):

```bash
kill "$(cat run/cluster/node$NODE/node.pid)"   # then wait for exit
(cd run/cluster/node$NODE && set -a && source env.$NODE && set +a \
  && nohup "$NEW_BIN" run --config node.yaml --shard 0 >> live.log 2>&1 & echo $! > node.pid)
```

## 4. Height-catch-up check

The upgraded node must rejoin and finalize. Allow catch-up time (minutes on
a real chain), then:

```bash
# Upgraded node vs a peer still on the old binary:
for P in 18646 18647; do
  echo -n "rpc $P: "
  curl -s -m 5 -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    http://127.0.0.1:$P | grep -oE '"result":"0x[0-9a-fA-F]+"'
done
grep 'FINALIZED block #' run/cluster/node$NODE/live.log | tail -3
curl -s $EXP/api/version   # version string must now be the NEW build

# No integrity regressions on the returnee:
curl -s $EXP/metrics | grep -E '^stell_(fork_total|divergence_total|weak_qc_refused_total|nil_breaker_fires_total|persist_queue_dropped_total)'
# All must be flat vs the step-0 baseline (compare values, not just presence).
```

Pass criteria: new version string, height within a few blocks of peers and
advancing, fresh `FINALIZED block #` lines in `live.log`, integrity counters flat.

## 5. Roll back (only if step 4 fails)

Rollback triggers (ANY one is enough):
- height frozen > 10 min while peers advance (`FinalsStalled` semantics);
- `stell_fork_total` / `stell_divergence_total` / `stell_weak_qc_refused_total` increasing;
- crash loop (pid dies repeatedly; `live.log` ends in panic);
- `/metrics` or `/health` unreachable 5+ min post-boot (not just slow sync).

```bash
./scripts/local-cluster.sh stop $NODE
# Restore the data dir from the verified snapshot (copy back, never move the only copy):
rm -rf run/cluster/node$NODE/data
cp -a /tmp/opencode/stell-upgrade-node$NODE/snapshot run/cluster/node$NODE/data
# Restore the old binary, boot, re-run step 4:
./scripts/local-cluster.sh start $NODE
```

Then report: old vs new version strings, last good height, first bad symptom
with log lines. Do not retry the same binary without a fix.

## 6. Roll forward (whole cluster, only after one node passes)

One node at a time, `stop → swap → start → step-4 checks`, never in parallel.
`./scripts/local-cluster.sh status` must show all nodes advancing between each
swap. `reset` (wipe data) is NEVER part of an upgrade — it is a fresh-boot
tool and destroys the state you just verified.
