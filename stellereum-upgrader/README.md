# stellereum-upgrader

`stellereum-upgrader` is the operator-side supervisor for a coordinated
Stellereum binary upgrade. It replaces the "someone must be awake at 03:00 to
swap the binary the moment the chain halts" procedure with a small, auditable,
fail-closed tool.

The crate is intentionally separate from the node. It has its own workspace
(`stellereum-upgrader/Cargo.toml`), depends only on `sha2`, `serde_json` and
`ureq`, and never links consensus or state code.

> Status: implemented and covered by lifecycle tests. It is **not yet part of
> the live four-validator rollout**; the first real coordinated use is still an
> operational step. See `docs/OPEN_DEFECTS.md` (UP-5) and
> `docs/UPGRADE_AND_RECOVERY.md` §7.

## The problem it solves

A Stellereum upgrade is not a rolling restart. The chain commits a single
upgrade plan, halts at the plan's height, and refuses to run old rules after
that point. Doing the swap by hand has three failure modes:

* the operator is asleep, so the chain stays halted;
* the operator swaps in the wrong bytes, so the node runs a binary the plan
  never authorised;
* the operator restarts before a supermajority of validators is on the new
  fork, so the fleet splits between observers and voters.

The upgrader removes the first two. The node's restart gate removes the third.

## Exact lifecycle

1. **Governance commits a plan.**
   `GovAction::SoftwareUpgrade { name, height, sha256 }` is proposed, voted on,
   and timelocked for `GOV_TIMELOCK_HEIGHTS = 90_000` blocks
   (`stellereum/src/governance.rs`). When the timelock matures and the
   execution gate is active, the plan is stored in
   `applied.upgrade_plan`. The plan's own `height` is chosen separately and is
   the real lead time; the timelock only delays when the plan becomes
   executable.

2. **The halt height arrives.**
   On the finalize lane, when `plan.height <= finalized_height`, the node
   drains persistence, snapshots state and domains, writes
   `data/upgrade-halt.marker`, and exits with code **42**
   (`stellereum/src/node/upgrade_halt.rs`, `node/consensus_driver.rs`). The
   marker is the durable proof of the halt:

   ```text
   stell-upgrade-halt v1
   height=<plan height>
   halted_at_height=<height actually finalized when this node halted>
   plan_name=<name>
   plan_sha256=<64 lowercase hex characters>
   target_version=<name>
   running_version=<version of the halting binary>
   halted_unix=<seconds since the Unix epoch>
   ```

3. **The upgrader obtains the authoritative plan.**
   It reads the marker and/or the committed plan over
   `stell_governanceParams` (`result.applied.upgrade_plan`). If both are
   present, `(name, height, sha256)` must match exactly or the upgrader
   refuses. If the node's RPC is already down because it exited 42, the
   marker alone is sufficient and authoritative.

4. **It verifies the staged bytes.**
   The staged file must be a regular file, not a symlink, with no symlinked
   parent, not world-writable, at most 512 MiB, and its SHA-256 must equal the
   plan's 32-byte digest exactly. Nothing is written before this passes.

5. **It performs an atomic swap.**
   A temporary file is created in the live binary's own directory, written,
   `fsync`ed, chmod `0755`, renamed over the live path, and the directory is
   `fsync`ed. A crash leaves either the old binary or the new binary, never a
   half-written one.

6. **It restarts the service.**
   Watcher mode runs the operator-supplied `--restart-cmd` through `sh -c`.
   Supervisor mode (`--supervise`) respawns the node itself and can set
   `STELL_WAIT_SUPERMAJORITY=<plan.height>` and
   `STELL_UPGRADE_VERSION=<plan.name>` for the new process.

7. **The upgraded node proves itself.**
   On startup the node's halt guard compares the running executable digest or
   `STELL_UPGRADE_VERSION` with the marker. Only when it matches does it clear
   the marker and join consensus. With `STELL_WAIT_SUPERMAJORITY` set, it
   first waits until strictly more than 2/3 of the committed power is present
   on the same `fork_id` and `protocol_version`; on timeout it stays up as an
   observer (RPC/sync only, no propose or vote).

There is **no automatic rollback**. Once a block above the halt height is
finalized under the new rules, restoring the old binary is not a rollback; it
is a new-genesis decision.

## Build

```sh
cargo build --release -p stellereum-upgrader
# binary: target/release/stellereum-upgrader
```

The crate is a member of the repository-root workspace. It can also be built
directly with `cargo build --release --manifest-path stellereum-upgrader/Cargo.toml`.

## CLI reference

Run `stellereum-upgrader --help` for the same text from the binary.

| Flag | Meaning |
| --- | --- |
| `--marker PATH` | Halt marker written by the halted node. Default: `./data/upgrade-halt.marker`. |
| `--rpc URL` | Read the committed plan from `stell_governanceParams` (`result.applied.upgrade_plan`). The RPC plan and the marker plan must agree when both exist. |
| `--staged PATH` | Path to the staged target binary. Its SHA-256 must equal the plan digest. |
| `--staged-dir DIR` | Resolve the staged binary as `<DIR>/<plan_name>/stellereum`; the plan name must be a safe single path segment. Cannot be combined with `--staged`. |
| `--live PATH` | The live binary to replace atomically. Required by `--apply` and by `--supervise`. |
| `--restart-cmd CMD` | Command run after the rename, via `sh -c` (for example `systemctl --user restart stellereum`). Required by `--apply` in watcher mode; forbidden with `--supervise`. |
| `--progress PATH` | Append-only progress journal. Default: `./data/upgrade-supervisor.progress`. |
| `--wait-timeout SECS` | Bound for waiting on a plan or marker. Default `3600`; capped at `86400`. |
| `--poll-ms MS` | Poll interval. Default `500`; capped at `60000`; clamped to at least 10 ms. |
| `--apply` | Actually replace the binary and restart/respawn. Without it the tool is a **dry run**. |
| `--allow-root` | Permit `--apply` while effective UID is 0. Without it, a root-owned rename is refused. |
| `--no-wait` | Do not block for the halt marker; read it once (inspection/dry-run). |
| `--supervise` | Own the node process: spawn `--live` with trailing `-- NODE_ARGS...`, catch exit 42, verify, swap, respawn. Requires `--live`; cannot use `--restart-cmd`. |
| `--set-wait-supermajority` | On a `--supervise` respawn after an upgrade, set `STELL_WAIT_SUPERMAJORITY=<plan.height>` and `STELL_UPGRADE_VERSION=<plan.name>`. |
| `--print-systemd` | Print reference systemd units for both modes and exit. Needs no other flag. |
| `-- NODE_ARGS...` | Everything after `--` is passed to the node only in `--supervise` mode. |

### Dry-run is the default

With no `--apply`, the tool reads the plan, waits for the marker unless
`--no-wait` is set, verifies the staged bytes, prints what it proved, and
changes nothing. In `--supervise` mode without `--apply` it still catches exit
42, verifies the staged binary, then stops without swapping or respawning.

### Watcher mode (node unit owns the process)

```sh
# Dry run: read the plan, verify the staged bytes, change nothing.
stellereum-upgrader \
  --marker /srv/stellereum/data/upgrade-halt.marker \
  --staged /srv/stellereum/data/upgrades/v0.2.0/stellereum

# Apply once the plan and bytes are proven.
stellereum-upgrader \
  --marker /srv/stellereum/data/upgrade-halt.marker \
  --staged-dir /srv/stellereum/data/upgrades \
  --live /usr/local/bin/stellereum \
  --restart-cmd 'systemctl --user restart stellereum' \
  --progress /srv/stellereum/data/upgrade-supervisor.progress \
  --apply
```

The node's own unit should stop cleanly on 42 instead of crash-looping:

```ini
[Service]
Restart=on-failure
RestartPreventExitStatus=42
```

Then the watcher (a oneshot unit, a timer, or an operator shell) performs the
swap and explicitly restarts the node.

### Supervisor mode (the upgrader owns the process)

```sh
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

In this mode the upgrader catches exit code **42**, verifies the marker and
staged bytes, atomically replaces `--live`, and respawns it. Any other
non-zero exit is propagated and the live binary is left untouched.

### systemd examples

`stellereum-upgrader --print-systemd` prints both of these; the canonical copy
lives in `src/lib.rs::systemd_unit_example`.

```ini
# Option A: direct supervisor mode (stellereum-upgrader owns the child process)
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

```ini
# Option B: external watcher mode (node unit stops cleanly on exit code 42)
# In stellereum.service:
#   Restart=on-failure
#   RestartPreventExitStatus=42
# Then run:
#   stellereum-upgrader --marker /srv/stellereum/data/upgrade-halt.marker \
#     --staged /srv/stellereum/data/upgrades/v0.2.0/stellereum \
#     --live /srv/stellereum/bin/stellereum \
#     --restart-cmd 'systemctl --user restart stellereum' \
#     --apply
```

## Security rules

The supervisor is deliberately narrow. Every refusal below is implemented in
`src/lib.rs` and covered by tests:

* **No symlinks.** A staged binary or its parent that is a symlink is refused.
  A live path that is a symlink or a directory is refused.
* **No world-writable bytes.** A staged file or its parent with mode `0o002`
  set is refused, because another local user could swap the bytes between the
  digest check and the rename.
* **Exact digest.** The plan digest is exactly 32 bytes; an all-zero digest is
  refused, as is any SHA-256 mismatch. The tool hashes the same bytes it then
  installs.
* **Bounded input.** A staged binary larger than 512 MiB is refused, including
  a file that grows past the cap while being read.
* **Safe plan names.** `--staged-dir` only accepts a plan name that is a
  single ASCII path segment (`v0.2.0`, `2026-11-22_hotfix.1`); `.`, `..`,
  leading dots, slashes and backslashes are refused.
* **No silent root rename.** Running as root with `--apply` is refused unless
  `--allow-root` is explicit. The normal deployment does not need root.
* **Atomic replacement only.** The verified bytes are written to a fresh
  same-directory temporary file, `fsync`ed, chmod `0755`, renamed, and the
  directory is `fsync`ed. The live binary is never truncated in place.
* **Restart command is code.** `--restart-cmd` is executed through `sh -c` and
  runs with the upgrader's privileges. Treat the unit file that contains it as
  security-sensitive.
* **Audit trail.** Every step (`start`, `plan-rpc`, `halt-marker`, `verify`,
  `dry-run`, `install`, `restart`, `done`, `error`) is appended to
  `--progress` with a Unix timestamp. The journal is append-only.

The upgrader does **not** delete the halt marker. The upgraded node clears it
only after proving it is the binary the plan named. Deleting the marker by hand
is the one action that can let old rules rejoin a post-upgrade chain.

## Real drill

The repository ships an executable rehearsal on a throwaway loopback cluster:

```sh
(cd stellereum && cargo build --release)
cargo build --release -p stellereum-upgrader
./scripts/upgrade_supervisor_drill.sh --plan-name drill-v2
```

The drill synthesizes the real v1 marker after a graceful stop, exercises the
refusals (digest mismatch, symlink, world-writable file), performs the atomic
swap and restart, runs the supermajority gate, verifies that the marker is
cleared and the chain resumes above the halt height, and exits non-zero on any
failure. Its last line is machine-readable:

```text
SUP_DRILL_RESULT=PASS halt=... resumed=... plan=... sha256=... log_dir=...
```

The broader stop/swap/restart rehearsal lives in `scripts/upgrade_drill.sh`
(`--mode manual --local-only`) and is documented in `docs/UPGRADE_DRILL.md`.

## Tests

The crate has unit tests for parsing, digest verification, symlink and mode
refusals, atomic install, and progress journalling, plus CLI lifecycle tests
that run the real binary in watcher and supervisor modes. Run:

```sh
cargo test -p stellereum-upgrader
```

The checked-in suite is 19/19 green as recorded in `docs/OPEN_DEFECTS.md`
(UP-5).

## Related reading

* `docs/UPGRADE_AND_RECOVERY.md` — full upgrade, halt, rollback and recovery
  design.
* `docs/UPGRADE_DRILL.md` — the two drills and what each proves.
* `stellereum/src/node/upgrade_halt.rs` — marker format, startup guard and
  supermajority restart gate.
* `docs/TESTNET_STATUS.md` — what is live today and what is still an
  operational follow-up.
