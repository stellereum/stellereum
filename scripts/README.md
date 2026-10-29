# Cluster operations scripts

The tooling that answers the questions the cluster itself does not answer.
Everything here was written after the 4-validator deployment attempt
(2026-10-21), where five real incidents produced **no log evidence at all**:
a node that filled every inode and dropped out of consensus, a node that was
silently isolated on a different pubsub topic, a node stuck behind a stale
consensus lock, a node whose binary was deleted from under it by
`cargo clean`, and a node that was simply down.

The full runbook is in [`../stellereum/docs/OPERATIONS.md`](../stellereum/docs/OPERATIONS.md)
§15 ("Что делать, когда сеть встала") and in
[`../stellereum/scripts/four-node/FAULT_RUNBOOK.md`](../stellereum/scripts/four-node/FAULT_RUNBOOK.md).

## The scripts

| Script | What it does | Writes? |
| --- | --- | --- |
| `stell-sync.sh preflight` | **Fail-closed** pre-deploy gate. Names every difference between the nodes and refuses to deploy. | no |
| `stell-sync.sh health` | The health screen + the per-node **cluster table**: service state (DOWN / CRASH-LOOPING are named), inode usage, orphan chunk count, pubsub topic, consensus lock, binary path + hash, last exit code. | no |
| `stell-sync.sh topic <node>` | The pubsub topic a node uses, and the one it should be on. | no |
| `stell-sync.sh lockclear <node> [--force]` | Clears a stale consensus lock safely (stop → verify → clear → start). | **yes** |
| `stell-sync.sh doctor [node] [--json]` | Single-node diagnosis. | no |
| `doctor.sh` | The same diagnosis, standalone, ON a node. | no |
| `node-prune-cron.sh` | The orphan-chunk + snapshot retention sweeper. **Run it on every node.** | **yes** |
| `cluster-watchdog.sh` | Watches the cluster, alerts, auto-heals the safe cases. | **yes** |
| `tools/stelops/` | The ops tool that reads the store (consensus checkpoint, genesis root) and clears the lock. | **yes** (the lock only) |
| `cluster-nodes.conf` | The cluster topology and the values every node must agree on. | no |
| `lib/nodeprobe.sh` | The per-node probe (run locally or piped over ssh). | no |
| `systemd/` | The sweeper's systemd service + timer. | no |

Every script takes `--help`, is non-interactive, is idempotent, and is safe
to run concurrently on several nodes.

## Quick start

```sh
cd /home/imm/stellereum-project

# 1. is the cluster even consistent? (fail-closed, exit 1 = do not deploy)
scripts/stell-sync.sh preflight

# 2. what does the cluster look like right now?
scripts/stell-sync.sh health

# 3. one node in detail
scripts/stell-sync.sh doctor C
scripts/stell-sync.sh doctor C --json

# 4. the disk (INODES, not bytes) and the chunk garbage
scripts/stell-sync.sh health | grep -i inode
ssh -p 2222 root@77.110.96.68 'scripts/node-prune-cron.sh --dir /root/nodeC --dry-run'

# 5. a node that does not rejoin (a stale consensus lock)
scripts/stell-sync.sh lockclear C            # the plan; the node is NOT touched
scripts/stell-sync.sh lockclear C --force    # stop, verify, clear, start

# 6. keep watching
scripts/cluster-watchdog.sh --interval 60
```

## Installing the sweeper on a node

```sh
# on EVERY node — one node without the sweeper is a single point of failure
cp scripts/systemd/stell-node-prune.service /etc/systemd/system/
cp scripts/systemd/stell-node-prune.timer   /etc/systemd/system/
# edit WorkingDirectory/ExecStart in the .service to THIS node's directory
systemctl daemon-reload
systemctl enable --now stell-node-prune.timer
```

## Building the ops tool

```sh
cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml
# -> scripts/tools/stelops/target/release/stelops
```

It depends on `sled` only, so it builds offline in seconds and can be copied
to a node without rebuilding the validator. `stell-sync.sh lockclear` stages
it on the remote node automatically.

## The cluster topology file

`cluster-nodes.conf` is the single source of truth for *where* the nodes are
and *what* they must agree on. It is machine-readable on purpose: the
topology is exactly what drifted during the deployment attempt
(`env.C` had `STELL_SHARDS=0` while the others had `0,1`). Override it with
`STELL_CONF=/path/to/other.conf`.
