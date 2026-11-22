# Operations scripts

This directory holds the operator tooling for a Stellereum node and the
four-validator testnet. The scripts exist because the node's own logs did not
answer the questions that actually stopped the chain: a full inode table, a
node on the wrong pubsub topic, a stale consensus lock, a binary deleted under
a running process, and a silent execution divergence.

The full incident procedure is in
[`../stellereum/docs/OPERATIONS.md`](../stellereum/docs/OPERATIONS.md) §15.
Topology lives in [`cluster-nodes.conf`](cluster-nodes.conf); the per-node
probe is [`lib/nodeprobe.sh`](lib/nodeprobe.sh).

Run every command from the repository root unless noted. All paths below are
relative to the repository root.

## Safety classes

| Class | Meaning |
| --- | --- |
| **read-only** | Reads the cluster, node, store or repository; writes nothing that affects a node. May write a log/textfile/report path named by the operator or a local build/test artifact. |
| **safe auto-heal** | Performs only a bounded, reversible repair whose target is unambiguous: restart a dead service, delete chunks no manifest references. Never guesses intent. |
| **mutating** | Writes local files, generated artifacts, a backup archive, a git worktree or a new node home. Does not mutate a running cluster. |
| **live-cluster** | Can stop/start nodes, replace a binary, wipe `./data`, or send transactions. Dry-run by default where possible; requires an explicit human order for the live cluster. |

`AGENTS.md` §6 applies: the live cluster is read-mostly. No restart, transaction,
stake or key operation without an explicit human order.

## Scripts

| Script | Purpose | Arguments | Safety class | Exact invocation |
| --- | --- | --- | --- | --- |
| [`join-testnet.sh`](join-testnet.sh) | External operator onboarding for two roles: full non-validating **observer** or **validator** preparation (hot Falcon key, cold withdrawal key, `node.yaml`, `node.env`, snapshot, registration instructions). Existing keys are never overwritten; `node.yaml`/`node.env` are kept unless `--force`; the generated environment keeps `STELL_OBSERVER=1` until registration, and `--start` launches the node. | `--mode observer\|validator`; `--home DIR`; `--name NAME`; `--listen ADDR:PORT`; `--advertise IP:PORT`; `--rpc ADDR:PORT`; `--explorer ADDR:PORT`; `--seeds DOMAINS`; `--peers-file FILE`; `--snapshot-url URL`; `--skip-snapshot`; `--binary PATH`; `--chain-id ID`; `--commission-bps N`; `--force`; `--start`; `--non-interactive`; `-h/--help`. | mutating (new host only; 0700 dirs, 0600 secrets) | `scripts/join-testnet.sh --mode observer --name observer-1 --advertise 203.0.113.10:9411 --home "$HOME/stell-observer" --non-interactive` |
| | Validator preparation (does **not** start unless `--start`). | Same as above plus `--commission-bps`. | mutating (new host only) | `scripts/join-testnet.sh --mode validator --name validator-1 --advertise 203.0.113.10:9410 --home "$HOME/stell-validator" --commission-bps 1000 --non-interactive` |
| [`run-observer.sh`](run-observer.sh) | One-command observer runner: creates `observer.yaml` and `env.observer`, downloads the HTTP snapshot if `data/store` is absent, then `exec`s the node. | Positional `NODE_DIR` (default `$HOME/stell-observer`); env `STELL_BIN`, `STELL_OBSERVER_PEERS_FILE`, `STELL_RPC_LISTEN`, `STELL_EXPLORER_LISTEN`. | mutating (new host only) | `scripts/run-observer.sh "$HOME/stell-observer"` |
| [`cluster_liveness.sh`](cluster_liveness.sh) | Read-only liveness/divergence check: tip advancing, heights within one block, common-height block hashes, per-node `/health`, round, peers and rejected-proposal diagnostics. Exit `0` OK, `1` STALLED, `2` DIVERGED, `64` usage. | `--rpcs SPEC` (or `STELL_RPCS`); `--health-rpcs SPEC`; `--interval SEC`; `--window SEC`; `--expected-block-time SEC`; `--stall-factor N`; `--timeout SEC`; `--min-reachable N`; `--journal CMD` (repeatable); `--journal-last N`; `--journal-scan N`; `--help`. | read-only | `scripts/cluster_liveness.sh --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" --expected-block-time 1 --window 30` |
| [`cluster_liveness_watch.sh`](cluster_liveness_watch.sh) | Periodic wrapper around `cluster_liveness.sh`; appends `LIVENESS_RESULT=` lines and atomically writes Prometheus textfile gauges (`stell_cluster_liveness_ok`, height, spread, stalled seconds, tick/clock metrics). | `--watch-interval SEC`; `--log FILE`; `--textfile FILE`; `--journal CMD`; `--clock CMD`; `--tick-window SEC`; `--tick-lines N`; `--tick-timeout SEC`; `--clock-timeout SEC`; `--once`; `--quiet`; forwards `--rpcs`, `--window`, `--interval`, `--expected-block-time`, `--stall-factor`, `--min-reachable`, etc. | read-only (writes only `--log` and `--textfile`) | `scripts/cluster_liveness_watch.sh --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" --log /var/log/stell/liveness.log --textfile /var/lib/node_exporter/textfile_collector/stell_liveness.prom --once` |
| [`cluster-watchdog.sh`](cluster-watchdog.sh) | Watches DOWN/CRASH-LOOP, topic drift, inode pressure, orphan chunks, stalled tip and DIVERGENCE. Auto-heals only a dead enabled service and unreferenced orphan pruning; reports config drift, stale lock, lag and divergence. | `--interval SEC`; `--once`; `--no-heal`; `--json`; `--stall-seconds N`; `--state-file PATH`; `--help`. | safe auto-heal | `scripts/cluster-watchdog.sh --interval 60` (or `--once --json` for a probe) |
| [`node-prune-cron.sh`](node-prune-cron.sh) | Deletes orphan DHT chunk files that no manifest in `kv.json` references, older than the grace period, under a delete cap; refuses when `kv.json` is stale. Safe while the node runs; idempotent; `flock`-guarded. | `--dir DIR`; `--data-dir DIR`; `--grace-seconds N`; `--max-kv-age N`; `--max-delete N`; `--dry-run`; `--json`; `--help`. | safe auto-heal | `scripts/node-prune-cron.sh --dir /root/nodeA --dry-run` then without `--dry-run` on every node |
| [`stell-sync.sh`](stell-sync.sh) | Cluster management front end: `status`, `health`, `preflight`, `lockclear <node> [--force]`, `topic <node>`, `doctor [node] [--json]`, `sync`, `auto-heal`, `deploy`, `restart`. `preflight` is fail-closed and names every drift. | Command plus command-specific options: `health` accepts `--rpc URL`, `--indexer URL`, `--timeout SEC`, `--no-orphans`, `--nodes "A B C D"`. | read-only for `status`/`health`/`preflight`/`topic`/`doctor`; **live-cluster** for `lockclear`, `sync`, `auto-heal`, `deploy`, `restart` | `scripts/stell-sync.sh preflight`; `scripts/stell-sync.sh health`; `scripts/stell-sync.sh topic C`; `scripts/stell-sync.sh lockclear C --force` |
| [`doctor.sh`](doctor.sh) | Diagnoses one node locally: config drift, inodes, orphan chunks, consensus checkpoint, pubsub topic, binary path/hash/target-dir, key format, chain id, base fee. Read-only; POSIX `sh`; non-interactive. | `--dir DIR`; `--service NAME`; `--scope system\|user`; `--rpc URL`; `--shard-id N`; `--json`; `--quiet`; `--help`. | read-only | `scripts/doctor.sh --dir /root/nodeA --service stell-nodeA.service --scope system --json` |
| [`lib/nodeprobe.sh`](lib/nodeprobe.sh) | The `key=value` probe used by the health/doctor/watchdog stack. Not executed directly; pipped to a shell locally or over ssh. | Env: `STELL_PROBE_NODE`, `STELL_PROBE_DIR`, `STELL_PROBE_SERVICE`, `STELL_PROBE_SERVICE_SCOPE`, `STELL_PROBE_RPC`, `STELL_PROBE_BINARY`, `STELL_PROBE_SHARD_ID`, `STELL_PROBE_ORPHANS`, `STELL_PROBE_ENV_FILE`. | read-only | `ssh root@host 'STELL_PROBE_NODE=A STELL_PROBE_DIR=/root/nodeA STELL_PROBE_SERVICE=stell-nodeA.service sh -s' < scripts/lib/nodeprobe.sh` |
| [`fresh_genesis.sh`](fresh_genesis.sh) | Coordinated fresh-chain boot: preflight disk/layout, stop all, replace binary, wipe only `./data`, set `STELL_NEW_CHAIN=1`, start, wait for height > 0, remove the flag. Dry-run by default; `--yes` to destroy. | `--nodes SPEC` (required, `A=ssh:user@host:/dir,B=local:/dir`); `--binary PATH`; `--keep-binary`; `--yes`; `--dry-run`; `--timeout SEC`; `--min-free-gb N`; `--log-lines N`. | live-cluster (destructive; dry-run default) | `scripts/fresh_genesis.sh --nodes "A=ssh:root@host:/root/nodeA,B=local:/home/imm/stellereum-project/multinode/nodeB" --binary stellereum/target/release/stellereum` |
| [`upgrade_drill.sh`](upgrade_drill.sh) | Throwaway-cluster stop/swap/restart rehearsal. `manual` works today; `onchain` fails closed while the upgrade execution gate is `u64::MAX`. Loopback only. | `--mode manual\|onchain`; `--local-only` (required); `--nodes N`; `--binary PATH`; `--new-binary PATH`; `--plan-name NAME`; `--plan-height N`; `--staged-bin PATH`; `--submit-cmd CMD`; timeouts. | mutating (local throwaway only) | `scripts/upgrade_drill.sh --mode manual --local-only --nodes 3` |
| [`upgrade_supervisor_drill.sh`](upgrade_supervisor_drill.sh) | Rehearses the `stellereum-upgrader` lifecycle: marker → digest/symlink/world-writable refusals → atomic swap → restart → supermajority gate → resume. Solo loopback cluster under `/tmp/opencode`. | `--supervisor PATH` (or `SUPERVISOR_BIN`); `--binary PATH` (or `STELL_BIN`); `--new-binary PATH`; `--plan-name NAME`; `--keep`; `--purge-on-pass`; `--help`. | mutating (local throwaway only) | `scripts/upgrade_supervisor_drill.sh --plan-name drill-v2` |
| [`soak_two_shard.sh`](soak_two_shard.sh) | Real two-shard live soak: heights, independent determinism pair, 2PC exactly-once, replay option. Real processes and JSON-RPC; default 30 minutes. | `--duration SEC`; `--interval SEC`; `--amount NANO`; `--replays N`; `--base-dir PATH`; `--bin PATH`; `--dev`; `--keep`; `--help`. | mutating (local processes only; `--dev` uses the public dev faucet key — never on a live network) | `scripts/soak_two_shard.sh --duration 600 --keep` |
| [`local-cluster.sh`](local-cluster.sh) | Local N-validator cluster under `run/cluster/`; two-phase key/config generation; optional `{0,1}` mode. Never touches `multinode/`, live configs or `/root`. | `up [N] [--shards 0,1]`; `up2 [N]`; `status`; `stop [i]`; `start [i]`; `restart [i]`; `down`; `reset`; `chaos`. | mutating (local `run/cluster/` only) | `scripts/local-cluster.sh up 4`; `scripts/local-cluster.sh status`; `scripts/local-cluster.sh down` |
| [`backup_offhost.sh`](backup_offhost.sh) | Off-host backup: copy-only staging of data + `node.yaml`, key inventory (names/modes only), SHA-256 manifest, encrypted tar, retention and an upload hook (dry-run by default; remote upload refused). | `--data-dir PATH` (required); `--node-yaml PATH`; `--out-dir PATH`; `--keep N`; `--passphrase-file PATH`; `--age-recipient RECIP`; `--upload-target PATH`; `--confirm-live`; `--dry-run`; `--help`. | mutating (archive only; live data read-only) | `scripts/backup_offhost.sh --data-dir /root/nodeA/data --node-yaml /root/nodeA/node.yaml --out-dir /root/backups --dry-run` |
| [`backup_verify.sh`](backup_verify.sh) | Copies a data dir to a temp work dir, checksums it, restores the image, verifies and performs a boot-read sanity check. Never writes into `--data-dir`. | `--data-dir PATH` (required); `--work-dir PATH`; `--keep-work-dir`; `--dry-run`; `--help`. | mutating (temp only) | `scripts/backup_verify.sh --data-dir /root/nodeA/data --dry-run` |
| [`backup_restore_drill.sh`](backup_restore_drill.sh) | Decrypts an off-host image into a fresh temp dir, verifies the shipped manifest, then calls `backup_verify.sh` on the restored copy. Never restores over a live path. | `--backup-dir DIR` or `--archive FILE` (exactly one); `--passphrase-file PATH`; `--work-dir PATH`; `--keep-work-dir`; `--use-age`; `--dry-run`; `--help`. | mutating (temp only) | `scripts/backup_restore_drill.sh --archive /root/backups/stell-nodeA.tar.gz.enc --passphrase-file /root/.backup.pass --dry-run` |
| [`status_snapshot.sh`](status_snapshot.sh) | Emits one JSON object describing this node's public status from verified RPC and explorer endpoints. Unreachable → `{"ok":false,...}`, never guessed values. | Env `RPC_URL` (default `http://127.0.0.1:8545`), `EXPLORER_URL` (default `http://127.0.0.1:8080`). | read-only | `RPC_URL=http://127.0.0.1:8545 EXPLORER_URL=http://127.0.0.1:8080 scripts/status_snapshot.sh` |
| [`verify_testnet_ideal.sh`](verify_testnet_ideal.sh) | The strict local gate: fake-code scan, clippy `-D warnings`, rustfmt, workspace tests, 4-node sim harness. | `--fast` (stellereum lib only); `--no-sim` (skip sim). | read-only (local build/test) | `./scripts/verify_testnet_ideal.sh --fast` |
| [`ci_local.sh`](ci_local.sh) | Reproduces the CI PR/nightly gate locally with `CARGO_NET_OFFLINE=true`; curated suites or `--full`. | `--full`; `--suite state\|...`; `--sdk`; `--loadtest`; `--help`. Env `JOBS`, `TEST_THREADS`. | read-only (local build/test) | `JOBS=8 TEST_THREADS=4 scripts/ci_local.sh --full` |
| [`test_parallel.sh`](test_parallel.sh) | Builds test binaries with cargo and runs them concurrently, one binary per worker slot. | `-p/--package NAME`; `--lib`; `--test`/`--test-item NAME`; `--bin NAME`; `--help`. Env `JOBS`, `TEST_THREADS`. | read-only (local build/test) | `JOBS=6 TEST_THREADS=4 scripts/test_parallel.sh -p stellereum --lib` |
| [`feature_matrix.sh`](feature_matrix.sh) | Runs the curated E2E test list, writes `artifacts/features.tsv`, `artifacts/features.json` and `FEATURES.md`. Exit non-zero on any RED. | None. | mutating (generated artifacts) | `scripts/feature_matrix.sh` |
| [`harness_status.sh`](harness_status.sh) | Regenerates `STATUS.md` and `artifacts/harness_status.json` from clippy and the fake-code scan. | None. | mutating (generated status) | `scripts/harness_status.sh` |
| [`check_import_graph.sh`](check_import_graph.sh) | Enforces crate/module import boundaries and rejects imports of stale `stellereum_head`/`w8` copies. | None. | read-only | `scripts/check_import_graph.sh` |
| [`clean_target.sh`](clean_target.sh) | Reclaims Cargo `target/` disk space. Dry-run by default; never removes `target/release`; destructive runs refuse while cargo/rustc is active. | `--dry-run`; `--yes/-y`; `--aggressive`; `--force`; `--target-dir PATH`; `--help`. | mutating | `scripts/clean_target.sh --yes` (default aggressive off) |
| [`export_audit_snapshot.sh`](export_audit_snapshot.sh) | Exports a tracked-files-only source snapshot with a SHA-256 manifest; hard-fails if secret-shaped paths are tracked. | Positional `OUT_DIR` (default `/tmp/opencode/audit-snapshot`). | mutating (out dir only) | `scripts/export_audit_snapshot.sh /tmp/opencode/audit-snapshot` |
| [`export_program_docs.sh`](export_program_docs.sh) | Mirrors root `docs/specs`, inventories and runbooks into `stellereum/docs/program/` for the GitHub crate mirror. Idempotent `cp -u`. | None. | mutating (docs mirror) | `scripts/export_program_docs.sh` |
| [`nightly_gate.sh`](nightly_gate.sh) | **Historical (2026-11-19)**: manual five-stage QA cron (clippy, lib, fuzz, matrix, audit-repro). Superseded by `.github/workflows/nightly.yml`; kept for manual/ops reference. | None. | mutating (generated matrix/artifacts) | `scripts/nightly_gate.sh` |
| [`print-dns-seed-txt.sh`](print-dns-seed-txt.sh) | Reads peer `pq-pub`/`endpoints` from `node.yaml` and prints valid `stellereum/v1` DNS TXT records (including the `inf1:` PQ id). | One or more `node.yaml` paths. | read-only | `scripts/print-dns-seed-txt.sh /root/nodeA/node.yaml /root/nodeD/node.yaml` |
| [`deploy-docs-site.sh`](deploy-docs-site.sh) | Builds and deploys the VitePress site (`docs-site/`) and nginx block to nodeA. | `--build-only`; `--no-cert`; `--no-reload`; `--help`. Env `DOCS_REMOTE`. | mutating (remote web root/nginx) | `scripts/deploy-docs-site.sh --build-only` |
| [`agents/spawn_worktrees.sh`](agents/spawn_worktrees.sh) | Creates an isolated git worktree for an agent scope and shares build caches. Development-only. | `<agent-id> <crate-subpath>`. | mutating (git worktree) | `scripts/agents/spawn_worktrees.sh w3 stellereum` |
| [`agents/merge_verified.sh`](agents/merge_verified.sh) | Merges only agent branches whose scoped gate passes; reports red branches unmerged. Development-only. | `<agents-base-dir>`. | mutating (git merge) | `scripts/agents/merge_verified.sh /path/to/agents-base` |
| [`tests/cluster_liveness_min_reachable_test.sh`](tests/cluster_liveness_min_reachable_test.sh) | Self-contained regression test for `cluster_liveness.sh --min-reachable` using fake `curl`/`date`/`sleep`. | None. | read-only | `scripts/tests/cluster_liveness_min_reachable_test.sh` |

## Rust tools in this directory

Both tools are standalone crates with their own `[workspace]`; neither is part
of the node workspace.

| Tool | Purpose | Safety class | Exact invocation |
| --- | --- | --- | --- |
| [`tools/stelops`](tools/stelops/src/main.rs) | Reads a **stopped** node store: `checkpoint`, `genesis-root`, `meta <key>`, `doctor [--shards 0,1] [--shard-id N] [--text]`, `clear-lock --force`, `diverge <data-A> <data-B> [--shards]`. `clear-lock` is the only mutating command; it refuses without `--force`, backs up the checkpoint, and never touches the finalized pointer. | read-only; `clear-lock` is mutating (lock only) | `cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml` then `scripts/tools/stelops/target/release/stelops doctor /root/nodeA/data/store --text` |
| [`loadtest/loadtest`](loadtest/loadtest/src/cli.rs) | Standalone full-PQ load harness. **Dry-run by default**; sending requires `--allow-live`; non-loopback requires `--allow-remote`; known live hosts require `--operator-order`. Never funds accounts and never calls faucet/staking/governance. | read-only by default; live-cluster only with explicit flags | `cargo build --release --offline --manifest-path scripts/loadtest/loadtest/Cargo.toml` then `scripts/loadtest/loadtest/target/release/stell-loadtest --dry-run --senders 4` |
| | Live preflight (reads chain id, base fee, balances; sends nothing). | read-only | `scripts/loadtest/loadtest/target/release/stell-loadtest --allow-live --preflight-only --url http://127.0.0.1:8545 --senders 64` |
| | Live wave on a local test node. | live-cluster (loopback) | `scripts/loadtest/loadtest/target/release/stell-loadtest --allow-live --url http://127.0.0.1:8545 --senders 64 --rate 60 --duration 900` |

## Supporting files

| File | Purpose |
| --- | --- |
| [`cluster-nodes.conf`](cluster-nodes.conf) | Machine-readable four-validator topology: ssh targets, directories, units, scopes, expected parameters. Override with `STELL_CONF=/path/to/other.conf`. |
| [`systemd/stell-node-prune.service`](systemd/stell-node-prune.service), [`systemd/stell-node-prune.timer`](systemd/stell-node-prune.timer) | Install the orphan-chunk sweeper on **every** node. Edit `WorkingDirectory`/`ExecStart` per node. |
| [`systemd/stellereum-indexer.service`](systemd/stellereum-indexer.service) | Indexer unit reference. |
| [`systemd/journald-stellereum.conf`](systemd/journald-stellereum.conf) | Suggested journald cap. |
| [`local-cluster.md`](local-cluster.md) | Local-cluster and two-shard walkthrough. |
| [`nightly_ci_notes.md`](nightly_ci_notes.md) | Historical notes; see `docs/CI.md`. |
| [`agents/TASK_PROMPT_TEMPLATE.md`](agents/TASK_PROMPT_TEMPLATE.md) | Scope-lock template for agent work. |

## The safe guard pattern

Every destructive or live-facing script follows the same pattern. Use it as a
checklist before running anything new:

1. **Dry-run or plan first.** `clean_target.sh`, `fresh_genesis.sh`,
   `backup_*`, `upgrade_drill.sh`, `upgrade_supervisor_drill.sh`,
   `stellereum-upgrader`, and `stell-loadtest` all default to no change.
2. **One explicit escalation flag.** `--yes` for `fresh_genesis.sh` and
   `clean_target.sh`, `--apply` for the upgrader, `--force` for
   `lockclear`/`clear-lock`, `--allow-live` for load. A missing flag is not a
   prompt; it is a refusal.
3. **Fail closed on ambiguity.** `preflight` exits non-zero on any drift;
   `cluster_liveness.sh` exits `1`/`2`; the upgrader refuses a digest mismatch,
   a symlink, a world-writable file or disagreeing plan sources; the load
   harness refuses unknown flags and blocked hosts.
4. **Confine writes.** Backups and restore drills write outside the live data
   dir. `node-prune-cron.sh` deletes only unreferenced chunks and only after
   the grace period. `join-testnet.sh` keeps `0700`/`0600` permissions and
   never overwrites keys.
5. **Never auto-heal an ambiguous condition.** The watchdog restarts a dead
   service and prunes garbage; it reports config drift, a stale consensus
   lock, lag and divergence instead of guessing.
6. **Live cluster is read-mostly.** `AGENTS.md` §6: no restarts, transactions,
   stakes or key operations without an explicit human order. A read-only probe
   first is always the correct default.

For onboarding, start with:

```sh
scripts/join-testnet.sh --mode observer --name observer-1 \
  --advertise 203.0.113.10:9411 --home "$HOME/stell-observer" --non-interactive
```

Then verify with `scripts/status_snapshot.sh` and
`scripts/cluster_liveness.sh` before considering any write path.
