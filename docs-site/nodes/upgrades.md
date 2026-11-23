---
title: Upgrades
description: Governance SoftwareUpgrade, exit 42, the halt marker, stellereum-upgrader and systemd.
outline: deep
---

# Software upgrades

A Stellereum upgrade is a **governed, height-triggered binary swap**. The chain
decides the rules; the operator decides which bytes run on the box.

The two halves are deliberately separate:

1. **Governance** approves a plan (`name`, `height`, `sha256`) and commits it.
2. **The operator** stages the exact binary and either lets the node `execve`
   it (`STELL_AUTO_UPGRADE=1`) or lets the node halt with **exit code 42** and
   restarts it under a supervisor.

::: danger Read this before proposing an upgrade
The plan's `height` is the real lead time. The 90,000-height governance
timelock is only ~75 minutes at the 50 ms block floor and a few hours at live
tempo — not a human review window. Set `height` days out and stage the same
bytes on **every** node before it.
:::

## The governance action

`GovAction::SoftwareUpgrade { name, height, sha256 }`:

| Field | Rule |
| --- | --- |
| `name` | non-empty, ≤ 64 bytes, a safe single path segment (no `/`, no `..`, no leading `.`, ASCII only) |
| `height` | non-zero, and must still be in the future when applied |
| `sha256` | non-zero; the exact digest of the staged binary |

Propose it with the CLI:

```bash
stellereum gov propose \
  --falcon-key-file ./keys/falcon.key \
  --title "v0.2.0" \
  --action software_upgrade \
  --params '{"name":"v0.2.0","height":250000,"sha256":"<64 hex>"}'
```

or over RPC:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_submitProposal","params":{
  "title":"v0.2.0",
  "type":"software_upgrade",
  "name":"v0.2.0",
  "height":250000,
  "sha256":"<64 hex>",
  "token":"<api token>"
}}
```

The plan is committed: `commitment.rs` hashes its presence, name, height and
sha256 into the state digest. A local-only plan cannot hide behind an identical
root.

### Timeline

| Phase | Duration / trigger |
| --- | --- |
| Voting | **3 days** (`GOVERNANCE_VOTING_PERIOD_SECS`) |
| Quorum | `quorum_bps = 6666` (2/3 of the frozen electorate) |
| Passing condition | quorum reached and `yes > no` |
| Timelock after pass | `GOV_TIMELOCK_HEIGHTS = 90,000` heights |
| Execution | deterministic governance sweep; `SoftwareUpgrade` filtered by the upgrade-exec gate |
| Halt | first applied block with `plan.height <= height` |

There is **no proposer-only execution gate**: any account (with the operator's
RPC token) can execute a passed proposal, so a lost proposer key cannot brick
the upgrade. `CancelUpgrade` is ungated and clears the plan before or after the
halt height.

::: warning The upgrade-execution gate is a genesis value
`UPGRADE_EXEC_ACTIVATION_HEIGHT` is compiled as `u64::MAX`, but the **effective**
height is `GenesisChainSpec::upgrade_exec_activation_height`, installed once
per process before the first block. A chain that leaves the default keeps the
old inert behavior; a chain that sets `H` at genesis installs a passed plan at
the first applied block at/after `H`. Until the genesis install call is wired
in production, an operator cannot set a non-default value and the compiled
default applies. Verify your chain spec before promising an on-chain upgrade.
:::

## The halt

The halt predicate is `plan.height <= height`, not `height == plan.height`.
A node that was offline at `H`, restarts, or snapshot-syncs past `H` still
refuses to keep running the old rules.

On the halt block the node:

1. finishes applying the block;
2. requests a flush, snapshots state and domains (these **enqueue** jobs);
3. writes a durable `upgrade-halt.marker`;
4. calls `std::process::exit(42)`.

The exit is not mid-block: consensus safety survives (the checkpoint is written
before the upgrade check), but durability is bounded by the persist queue. On
restart the node heals from the last paired snapshot; the loss is time, not
safety.

### Marker format

The marker is written at `./data/upgrade-halt.marker` (or
`$STELL_UPGRADE_HALT_MARKER`):

```text
stell-upgrade-halt v1
height=250000
halted_at_height=250000
plan_name=v0.2.0
plan_sha256=<64 hex>
target_version=v0.2.0
running_version=0.1.0
halted_unix=1758800000
```

Parsing is strict. A missing field, a bad digest or an all-zero `plan_sha256`
is refused. The startup guard compares the running binary's identity against
the plan before the node joins consensus.

Inspect it read-only:

```bash
stellereum upgrade-status
stellereum upgrade-status --marker /srv/stellereum/data/upgrade-halt.marker
```

`upgrade-status` never edits or clears the marker. It prints the marker path,
the halt height, the target version, the binary's version and whether the
running binary satisfies the plan.

## Staging the binary

The plan's `name` builds the candidate path. The node tries, in order:

```text
data/upgrades/<name>/stellereum
data/upgrades/<name>/bin/stellereum
/usr/local/bin/stellereum.new
```

The first path that exists and passes the hash check is staged. The staging
rules make the `exec` safe:

1. **Safe name.** Empty, >64 bytes, `/`, `\`, NUL, non-ASCII, `.`, `..`, or a
   leading `.` yields an empty candidate list; the node still halts with exit
   42 rather than continuing on the old rules.
2. **Regular file, not a symlink.** `symlink_metadata` is used; a symlinked
   candidate is refused.
3. **Size cap 512 MiB** (`MAX_UPGRADE_BINARY_BYTES`).
4. **Exact SHA-256.** Strict equality; all-zero is never a match.
5. **The bytes that were hashed are the bytes that run.** The verified bytes
   are copied into a fresh private directory (random name, `0700`, fsynced)
   and **that copy** is executed. This closes the check-to-exec TOCTOU.
6. **The candidate is not chmod-ed.** The copy is `0700`; the target of a
   planted symlink cannot be modified.
7. **The parent directory must be a real directory.** A symlinked parent is
   refused loudly.

Operator checklist:

```bash
install -d -m 700 data/upgrades/v0.2.0
install -m 755 /path/to/new/stellereum data/upgrades/v0.2.0/stellereum

sha256sum data/upgrades/v0.2.0/stellereum
test -L data/upgrades/v0.2.0/stellereum && echo "REFUSED: symlink"

# Stage the SAME bytes on EVERY node before the halt height.
```

A hash mismatch ends that candidate; the node does not fall back to
`/usr/local/bin/stellereum.new` after a mismatch on an existing file. The
network then runs two binaries. Stage and verify everywhere.

## Automatic `execve` vs exit 42

| `STELL_AUTO_UPGRADE` | Behavior |
| --- | --- |
| unset (default) | **0** — do not exec; halt with exit 42 |
| `1` / `true` | arm live migration: `execve` the verified staged binary in place |
| anything else (`0`, `false`, `yes`, typo) | do not exec; halt with exit 42 |

The default is **OFF**. A governance quorum decides the chain's rules; it is
not a decision to replace the binary on your box. Arming is node-local,
operator-local policy.

When armed, the node prints a loud banner at startup:

```text
================= STELLEREUM: LIVE MIGRATION ARMED =================
STELL_AUTO_UPGRADE=1 — LIVE MIGRATION ARMED: at an approved upgrade height this node will
exec() the SHA-256-verified new binary IN PLACE, without a supervisor.
...
```

Arm it on **every** node or on **none**.

::: danger Known open question about `execve`
With `STELL_AUTO_UPGRADE=1`, `execve` replaces the image while sled handles are
still open. sled's on-disk lock may survive `execve`; if it does, the new image
can fail to open the store. The staging rules prove *which bytes run*, not that
the storage lock is released. Rehearse on a throwaway cluster before arming
live migration.
:::

## `stellereum-upgrader`

`stellereum-upgrader` is a small, auditable Cosmovisor-like supervisor. It:

1. reads the plan from the marker or from `stell_governanceParams`
   (`result.applied.upgrade_plan`);
2. waits for the halt marker (a plan alone is not a halt);
3. verifies the staged binary's SHA-256, refusing a symlink or world-writable
   file;
4. atomically replaces the live binary via a same-directory rename of the
   exact verified bytes;
5. runs the restart command (or respawns in supervisor mode) and appends each
   step to a progress journal.

**Dry-run is the default.** `--apply` is required to touch the live binary.
The supervisor never needs root when the binary, marker and progress file are
owned by the service user and the restart command is user-scoped. Started as
root, `--apply` is refused unless `--allow-root` is passed.

### Usage

```text
stellereum-upgrader (--staged PATH | --staged-dir DIR) [--live PATH --restart-cmd CMD --apply] [OPTIONS]
stellereum-upgrader --supervise --live PATH (--staged PATH | --staged-dir DIR) [--apply] [OPTIONS] [-- NODE_ARGS...]
```

| Flag | Meaning |
| --- | --- |
| `--marker PATH` | halt marker written by the node (default `./data/upgrade-halt.marker`) |
| `--rpc URL` | read the committed plan via `stell_governanceParams`; if both marker and RPC are present they must agree |
| `--staged PATH` | staged binary; SHA-256 must match the plan; refuses symlink/world-writable |
| `--staged-dir DIR` | resolve `<DIR>/<plan_name>/stellereum` |
| `--live PATH` | live binary to atomically replace |
| `--restart-cmd CMD` | command run after the rename, via `sh -c` |
| `--supervise` | spawn `--live` with trailing `-- NODE_ARGS…`, catch exit 42, verify, swap, respawn |
| `--set-wait-supermajority` | on respawn, set `STELL_WAIT_SUPERMAJORITY=<plan.height>` and `STELL_UPGRADE_VERSION=<plan.name>` |
| `--print-systemd` | print reference unit examples and exit |
| `--apply` | perform the rename/restart (otherwise dry run) |
| `--allow-root` | permit `--apply` as root |
| `--no-wait` | do not block for the halt marker |
| `--wait-timeout SECS` | bound for waiting on plan/marker |
| `--poll-ms MS` | poll interval |
| `--progress PATH` | append-only journal |

### Supervisor mode (recommended)

```bash
stellereum-upgrader \
  --supervise \
  --live /srv/stellereum/bin/stellereum \
  --staged-dir /srv/stellereum/data/upgrades \
  --marker /srv/stellereum/data/upgrade-halt.marker \
  --progress /srv/stellereum/data/upgrade-supervisor.progress \
  --set-wait-supermajority \
  --apply \
  -- run --config /srv/stellereum/node.yaml --shard 0 --parallel-exec
```

The supervisor owns the child process, catches exit 42, verifies the marker and
staged binary, swaps the live binary and respawns.

### External watcher mode

The node's own unit stops cleanly on exit 42:

```ini
Restart=on-failure
RestartPreventExitStatus=42
```

Then a watcher performs the swap:

```bash
stellereum-upgrader \
  --marker /srv/stellereum/data/upgrade-halt.marker \
  --staged /srv/stellereum/data/upgrades/v0.2.0/stellereum \
  --live /srv/stellereum/bin/stellereum \
  --restart-cmd 'systemctl --user restart stellereum' \
  --apply
```

::: warning `Restart=always` + exit 42 is a crash loop
A unit with `Restart=always` restarts the **old** binary after exit 42. Unless
you replace the `ExecStart` path before `H`, the node halts again on the first
block it sees. Either use `RestartPreventExitStatus=42` (external watcher) or
`--supervise` (the supervisor owns the child). Do not rely on an implicit
"restart the same command line" contract.
:::

### Reference units

`stellereum-upgrader --print-systemd` prints both options:

**Option A — supervisor owns the child:**

```ini
[Unit]
Description=Stellereum Node (supervised by stellereum-upgrader)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/srv/stellereum
EnvironmentFile=/srv/stellereum/node.env
ExecStart=/usr/local/bin/stellereum-upgrader \
  --supervise \
  --live /srv/stellereum/bin/stellereum \
  --staged-dir /srv/stellereum/data/upgrades \
  --marker /srv/stellereum/data/upgrade-halt.marker \
  --progress /srv/stellereum/data/upgrade-supervisor.progress \
  --set-wait-supermajority \
  --apply \
  -- run --config /srv/stellereum/node.yaml --shard 0 --parallel-exec
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Option B — node unit stops on 42, watcher swaps:**

```ini
# stellereum.service
Restart=on-failure
RestartPreventExitStatus=42
```

```bash
stellereum-upgrader --marker /srv/stellereum/data/upgrade-halt.marker \
  --staged /srv/stellereum/data/upgrades/v0.2.0/stellereum \
  --live /srv/stellereum/bin/stellereum \
  --restart-cmd 'systemctl --user restart stellereum' \
  --apply
```

## Rollback

**Before the halt height `H`:** safe, if the old binary reads the same state
(same `COMMITMENT_VERSION`, same snapshot shapes) and derives the same genesis
root.

**After `H`:** **not supported.** Finalized blocks cannot be rewound. Restoring
a pre-`H` data directory puts the node behind a chain its old binary cannot
validate. The only rollback is a coordinated **new genesis** with a wiped
`./data` on every node.

Pin the previous binary and a backup before every upgrade:

```bash
# atomic deploy, never cp over a running binary
cp /path/to/new/stellereum ./stellereum.new && mv ./stellereum.new ./stellereum
cp ./stellereum ./stellereum.prev-<OLD-VERSION>
stellereum/scripts/backup/backup.sh --node A
```

State-compat check:

```bash
cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml
scripts/tools/stelops/target/release/stelops checkpoint /root/nodeA/data/store
scripts/tools/stelops/target/release/stelops genesis-root /root/nodeA/data/store
```

Rollback is safe when the genesis root matches the network and the old
binary's genesis constants match the store. If they do not, the old binary
exits with `genesis state root mismatch` — that refusal is the safety net, not
a bug.

## Live rolling deploy

A governed upgrade halts the chain at a height. A **rolling deploy** is the
other shape: replace the binary on one live validator at a time, with no
governance height and no halt. The constraint is not the binary, it is the
downtime jail.

### The restart budget

`DOWNTIME_MISS_THRESHOLD = 42` counts **consecutive missed heights**. Its length
in seconds is the block tempo, and the fleet is currently at
`STELL_MIN_BLOCK_MS=800` (the 1-vCPU hosts have no headroom at 400 ms):

```text
42 misses × 800 ms = 33 600 ms = 33.6 s   (live tempo)
42 misses × 400 ms = 16 800 ms = 16.8 s   (earlier tempo)
```

That is the entire budget between the last vote a validator casts and the first
one it casts after the restart. Past it, the chain jails the validator:
`release_height = jailed_at_height + 4000` — about **53 minutes at 800 ms**
(26 min 40 s at 400 ms) — plus a **0.1 %** downtime slash. A jailed validator
does not resume by itself, and the unjail transaction must be signed by the
**cold withdrawal key**, not by the hot voting key on the node.

The 2026-11-23 incident made this concrete: a rolling deploy copied a **43 MB**
binary to a 1-vCPU validator and restarted it in one window, at the 400 ms
tempo. The transfer starved the consensus thread on the single core, the restart
and the ~600-block catch-up followed, and the total exceeded 16.8 s. Node D was
jailed; A/B/C survived only because their windows were shorter. The fleet moved
to 800 ms and every binary is pre-staged for exactly this reason.

### Why the binary is pre-staged

Copying 43 MB to a small host is not a constant-time operation: page cache
pressure, disk write-back and one shared vCPU add seconds to tens of seconds,
and the copy competes with the process that must keep voting. If the copy and
the restart share one window, **the window is the copy plus the restart**. They
are therefore separate phases:

```bash
# Phase 1 — transfer and verify while the old binary keeps voting.
scripts/rolling-deploy.sh stage ./stellereum/target/release/stellereum

# Phase 2 — rename and restart, one node at a time.
scripts/rolling-deploy.sh activate
```

`stage <binary> [nodes...]`:

1. streams the file to `<node-dir>/stellereum.new.next` with
   `nice -n 19 ionice -c3` (falls back to `nice -n 19` when `ionice` is
   absent), so the transfer yields to consensus;
2. verifies the remote SHA-256 against the local file;
3. writes the expected digest to `<node-dir>/stellereum.new.sha256`;
4. never writes `<node-dir>/stellereum`. The running binary is untouched.

`activate [nodes...]` processes nodes **in sequence** and, per node:

1. preflights `stellereum.new.next` against `stellereum.new.sha256`; a missing
   file, symlink or digest mismatch refuses the node;
2. records `T0`, runs `cp -f stellereum stellereum.prev`,
   `mv -f stellereum.new.next stellereum`, then restarts the unit
   (`systemctl --user` for nodeB, `systemctl` elsewhere);
3. waits up to 120 s for `is-active`, then polls the node's local
   `stell_blockNumber` until it is within **5 blocks** of the public tip
   (`STELL_PUBLIC_RPC`, default `https://rpc.stellereum.org`);
4. prints the measured downtime from `T0` to that point — catch-up included,
   because a node replaying 600 blocks is not voting — and warns above
   **15 s**;
5. queries `stell_getValidatorStatus`; if the validator is jailed it prints
   `release_height`, an ETA in blocks and minutes, and the exact cold-key
   unjail command. It never auto-unjails unless both `--unjail-on-jail` and
   `--withdrawal-key-file` are given. A jail also stops the rollout;
6. re-checks `stell_getValidators` and **aborts the rollout** if the count
   drops below 3 or `fragile` becomes `true`. The next node is not touched.

### Downtime budget

| Interval | Budget |
| --- | --- |
| binary transfer + SHA-256 verification | **outside** the restart window (`stage`) |
| `cp`/`mv` + restart + `is-active` | inside the measured window (restart downtime) |
| local RPC reaching public tip − 5 | inside the measured window (catch-up) |
| measured `T0` → caught up | **warn above 90 %** of `42 × STELL_MIN_BLOCK_MS` |

The warning level is not a safety margin: at the live 800 ms tempo it is 30.2 s
against a 33.6 s jail, and at 400 ms it was 15.1 s against 16.8 s. If `activate`
warns, stop the rollout and investigate before restarting the next validator. A
node that has not caught up within `STELL_ROLL_DEPLOY_CATCHUP_SECS` (300 s) also
stops the rollout.

Selection and inspection:

```bash
# print the whole plan; contacts no node
scripts/rolling-deploy.sh --dry-run --nodes "A"

# one node, explicit validator id
scripts/rolling-deploy.sh activate --nodes D \
  --validator <64-hex-validator-id>

# a different reference endpoint
scripts/rolling-deploy.sh activate --public-rpc https://rpc.example.org

# stage a subset
scripts/rolling-deploy.sh stage ./stellereum/target/release/stellereum A C
```

The script reads `scripts/cluster-nodes.conf` for hosts, directories, units,
RPC ports and optional `NODE_<X>_VALIDATOR` ids. It never reads an env file and
never prints key material.

### If a validator is jailed

Read `release_height` from the status output. The node must stay up and keep
catching up; do **not** restart it again while it is jailed. When the chain
height reaches `release_height`, unjail with the cold key:

```bash
stellereum validator unjail \
  --validator-id <64-hex-validator-id> \
  --withdrawal-key-file /path/to/cold-withdrawal.key
```

If `withdrawal_address` is `null`, no unjail, unbond or withdrawal is possible
until a cold address is claimed (`stellereum validator claim-withdrawal`), which
also requires the cold key. Restarting the node, editing the store or reusing
the hot key does not clear a jail.

### Rollback

`activate` leaves the previous binary at `<node-dir>/stellereum.prev`:

```bash
cd /root/nodeD
mv -f stellereum.prev stellereum
systemctl restart stell-nodeD
```

This is the pre-`H` rollback: it is safe only while the old binary can read the
same store and derives the same genesis root. After a governed halt height it
is not supported — see [Rollback](#rollback).

## What an upgrade can and cannot change

| Change class | Mixed-version behavior |
| --- | --- |
| Wire/frame version | exact-match; old peers get no traffic — fail-closed isolation |
| Appended consensus message | old binary drops it — liveness loss, no fork |
| Height-gated state change | old nodes compute a different post-`H` root — stall, not fork |
| Sortition change | proposer/committee mismatch — stall |
| `ValidatorId` derivation | different genesis root — **different chain** |
| `COMMITMENT_VERSION` bump | different root for the same state — **genesis reset required** |
| Validator set / faucet / chain id | different genesis root / block hashes — **different chain** |

A topic is epoch-scoped by the genesis state root, so two different genesis
roots cannot even hear each other. A validator-set change is a hard partition,
not a fork of one chain.

## Pre-flight checklist

```text
[ ] Plan name is a safe path segment
[ ] Plan height is days in the future, not minutes
[ ] sha256sum of the staged binary equals plan.sha256
[ ] The candidate is a regular file, not a symlink
[ ] The same bytes are staged on EVERY node
[ ] `stellereum upgrade-status` shows the expected plan
[ ] A pre-upgrade backup of data/ and keys/ exists off-host
[ ] Restore has been rehearsed on a throwaway node
[ ] The unit uses --supervise OR RestartPreventExitStatus=42
[ ] STELL_AUTO_UPGRADE is identical on every node (off, unless deliberate)
[ ] A peer is reachable to compare state roots after the restart
```

## After the halt

1. The supervisor replaces the binary and restarts (or the operator does).
2. Verify the new binary: `stellereum --version`, `sha256sum` against the plan.
3. Watch the journal for the startup guard and the first finalized height.
4. Compare `stell_getStateRoot` and `stell_blockNumber` against a peer.
5. If the node refuses to start, read the marker and the startup guard line
   before touching data. A `genesis state root mismatch` means the binary or
   config does not match the chain, not that the store is corrupt.

## Next

Read [Operations](/nodes/operations) for the backup and lock-clear procedures an upgrade depends on, then [Monitoring](/nodes/monitoring) for the post-restart checks.
