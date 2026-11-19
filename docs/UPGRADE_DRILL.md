# Upgrade drill — executable rehearsal for the halt/upgrade machinery

**Status:** `scripts/upgrade_drill.sh` (`--mode manual`) was run end-to-end on a
throwaway 3-node local cluster on 2026-11-19. Result: **PASS**, measured
**RTO = 10.812 s** (stop → first new finalized block). The on-chain mode is
implemented as an orchestration around the block path but **fails closed today**
because `UPGRADE_EXEC_ACTIVATION_HEIGHT` is still `u64::MAX`; it never pretends
to pass. No production source was changed to make any check pass.

This document is the operator-facing companion to
[`UPGRADE_AND_RECOVERY.md`](UPGRADE_AND_RECOVERY.md) §1.2 (halt predicate,
drain, marker, exit 42, staging, `STELL_AUTO_UPGRADE`) and §2 (safe-upgrade
design). It exists because that material was **paper-only**: the tables and code
paths had not been exercised on a running cluster.

---

## 1. What the drill proves

### `--mode manual` (works today)

A full-cluster binary swap, performed the way an operator would do it:

1. three validators boot from the same tree and finalize an identical chain;
2. real PQ traffic is submitted and finalized (not just empty-block heights);
3. **all three are stopped with SIGTERM** and must exit `0` after the
   persistence drain — not by SIGKILL, and not via the drain-cap path;
4. the binary at the unit's `ExecStart` path is atomically replaced by a second
   copy from the same tree, with a distinct version marker/label;
5. all three restart on the new image and finalize again;
6. the pre-stop block hash **and** its QC-anchored historical state root are
   still identical after the restart (no reorg, no double-apply);
7. the faucet nonce/balance did not move across the restart, so no finalized
   transaction was applied twice;
8. all nodes agree on a common post-restart height and state root;
9. fork/divergence/weak-QC/dropped-persistence counters did not grow;
10. **RTO** is measured from the first SIGTERM to the first *new* finalized
    block on any node.

It proves the **durability and stop/swap/restart mechanics**. It does **not**
prove that a semantically different build reads old state correctly unless you
pass a genuinely different build with `--new-binary` (see §7).

### `--mode onchain` (for when the gate opens)

The intended end-to-end path is:

1. submit a `SoftwareUpgrade` through the **block path**
   (`SysCallGovPropose` / `SysCallGovVote` carriers, executed by the
   deterministic governance sweep) using an operator-supplied submitter;
2. wait for the plan to mature and the finalize lane to trigger at/past the
   planned height;
3. verify each node exits **42**, wrote a durable
   `data/upgrade-halt.marker`, and logged a completed persistence drain;
4. restart the **old** binary against the marker and require it to **refuse**
   (`REFUSING TO START CONSENSUS`) — the fail-closed guard;
5. install the plan-named staged binary, restart, verify the marker is cleared,
   the chain resumes above the halt height, the pre-halt history is unchanged,
   and every node agrees on the new common height.

**Today this mode refuses to run** (exit 1, no cluster started):

```
DRILL_RESULT=FAIL mode=onchain ... reason="on-chain execution is gated
(UPGRADE_EXEC_ACTIVATION_HEIGHT=u64::MAX); refusing to simulate a pass"
```

The gate is detected by parsing
`stellereum/src/governance.rs::UPGRADE_EXEC_ACTIVATION_HEIGHT` **before**
anything is started. A finite value opens the mode; `u64::MAX` (or an
unparseable value) keeps it closed. This is deliberate: a drill that "passes"
while `SoftwareUpgrade` is filtered out of the execution sweep would be worse
than no drill.

---

## 2. Exact commands

### Prerequisites

* A built `stellereum` binary (the drill never builds, so it cannot race the
  serialized cargo queue):
  ```bash
  CARGO_BUILD_JOBS=2 cargo build -p stellereum
  ```
* `bash`, `curl`, `python3`, `rustc`, and an existing
  `stellereum/target/{debug,release}/deps/libblake3-*.rlib` (the last two are
  used only to derive consensus validator ids; see §7 gap 8).
* `/tmp/opencode` must exist and be writable.

### Manual drill (3 nodes)

```bash
cd /path/to/stellereum-project
./scripts/upgrade_drill.sh --mode manual --local-only --nodes 3
```

`--local-only` is **mandatory**. The script also audits every generated
`listen` / `advertise` / `endpoints` address and aborts on anything that is not
loopback or RFC1918. It allocates free loopback ports dynamically and rejects
the documented live bases (`18646..18649`, `19411..19414`) even if free.

The generated configs set `STELL_MIN_BLOCK_MS=250` (instead of the live 50 ms
floor). This is a drill convenience: it keeps a run short and keeps the
pre-restart heights inside the durable header/body window. It does not skip or
weaken any check; the RTO number is therefore a local floor, not a production
SLO.

Useful flags:

| Flag | Meaning |
|---|---|
| `--nodes N` | Number of validators (default 3). `--nodes 1` is the constrained-host fallback (§6). |
| `--binary PATH` | Binary under test (default: `stellereum/target/debug/stellereum`, then release, then `$PATH`). |
| `--new-binary PATH` | The "upgraded" image. Default: a byte copy of the old binary with a new label/marker, which proves the swap mechanics. Pass a genuinely rebuilt binary to test state compatibility. |
| `--traffic-txs N` | Number of PQ transfers used as traffic (default 2; at least one must finalize). |
| `--rto-budget-seconds N` | Fail if RTO exceeds this (default 180). |
| `--ready-timeout`, `--resume-timeout`, `--stop-timeout` | Phase budgets (defaults 180/180/120 s). |
| `--purge-on-pass` | Delete the run directory after a PASS (logs are kept by default). |

### On-chain drill (gated today)

```bash
./scripts/upgrade_drill.sh --mode onchain --local-only
```

Expected today (exit 1, no processes started):

```
[drill] UPGRADE_EXEC_ACTIVATION_HEIGHT=u64::MAX (open=0)
[drill] FAIL: on-chain execution is gated (UPGRADE_EXEC_ACTIVATION_HEIGHT=u64::MAX); refusing to simulate a pass
DRILL_RESULT=FAIL mode=onchain ... reason="on-chain execution is gated ..."
```

When the gate is open, the mode requires:

```bash
./scripts/upgrade_drill.sh --mode onchain --local-only \
  --plan-name v0.2.0 \
  --plan-height 500 \
  --staged-bin /path/to/stellereum-v0.2.0 \
  --submit-cmd /path/to/block-path-submit.sh
```

`--submit-cmd` is an executable that submits the signed
`SysCallGovPropose`/`SysCallGovVote` transactions **through the block path** and
drives the proposal to execution. It receives:

```
DRILL_RPC_URLS=http://127.0.0.1:<rpc1>,...
DRILL_PLAN_NAME=v0.2.0
DRILL_PLAN_HEIGHT=500
DRILL_PLAN_SHA256=<sha256 of --staged-bin>
DRILL_STAGED_BIN=/path/to/stellereum-v0.2.0
DRILL_RUN_ROOT=/tmp/opencode/upgrade-drill-...
```

The drill validates the submitter's effect against the chain (exit 42, the
marker's `plan_name`/`height`/`plan_sha256`, the completed drain, the old
binary's refusal, and the unchanged pre-halt history) rather than trusting the
submitter's exit code.

---

## 3. Expected output (real run)

The 3-node run on 2026-11-19:

```
[drill] old binary: .../stellereum/target/debug/stellereum (sha256 bb6210e927707cf3…, label drill-old-bb6210e9)
[drill] UPGRADE_EXEC_ACTIVATION_HEIGHT=u64::MAX (open=0)
[drill] new binary: /tmp/opencode/upgrade-drill-20261119-102547-2016350/bin/stellereum-new (sha256 bb6210e927707cf3…, label drill-new-bb6210e9)
[drill] ports: p2p 32825..32827, rpc 32830..32832, explorer 32835..32837
[drill] node1 consensus-id=inf1:caa7978ec830bf4930a9339fc769019c4b296fe9 ...
[drill] node2 consensus-id=inf1:a56b6719365d8937ca056bb8f7eaa44b019edc97 ...
[drill] node3 consensus-id=inf1:c9850bd6c981b9fd6d3e518724f93efbb926d872 ...
[drill] endpoint audit: all addresses are loopback/private
[drill] cluster ready (epoch 86bc7a130ecc4ff8)
[drill] traffic applied: nonce 0 -> 1, balance 999999999674999
[drill] baseline: height 19 hash 08e8d7cc574d7390… state-root 75ef1fb7fa6ad8eb…
[drill] verified: all nodes execute .../bin/live/stellereum with label 'drill-old-bb6210e9'
[drill] node1 SIGTERM (pid 2016548)
[drill] node2 SIGTERM (pid 2016553)
[drill] node3 SIGTERM (pid 2016558)
[drill] all 3 nodes stopped gracefully in 10.587s
[drill] swap: installing 'drill-new-bb6210e9' over .../bin/live/stellereum
[drill] restarting all nodes on 'drill-new-bb6210e9' (RTO clock is running)
[drill] first new finalized block after 10.812s
[drill] verified: all nodes execute .../bin/live/stellereum with label 'drill-new-bb6210e9'
[drill] historical block 19 and its QC-anchored state root are unchanged
[drill] resumed: common height 67 hash ddebf3cec81365e1… state-root 29e120b91fff32cb…
[drill] PASS manual: 3 nodes, RTO 10.812s, heights 19 -> 67, state-root 29e120b91fff32cb…
[drill] artifacts kept at /tmp/opencode/upgrade-drill-20261119-102547-2016350
DRILL_RESULT=PASS mode=manual nodes=3 rto_ms=10812 rto_seconds=10.812 pre_height=19 post_height=67 state_root=29e120b91fff32cbf040ed49ba63997122660be27b642565bb1813c15ace281f gate=u64::MAX reason="" log_dir=/tmp/opencode/upgrade-drill-20261119-102547-2016350
```

The last line is the machine-readable result and is also written to
`$RUN_ROOT/summary.txt` and `$RUN_ROOT/summary.env`.

### Constrained-host fallback (real run)

A 1-node run (same script, `--nodes 1 --traffic-txs 1`) also passed:

```
DRILL_RESULT=PASS mode=manual nodes=1 rto_ms=10707 rto_seconds=10.707 pre_height=21 post_height=84 state_root=5f8c3a48cdf80e7ea1e4a7ee3345afc0d98a54206fca7e76c67bd16f4d97be81 gate=u64::MAX ...
```

It is **not** a substitute for the 3-node result: with one validator the
quorum is 1 and the "full cluster outage" is trivial. The 3-node result above
is the primary evidence.

---

## 4. Exact pass criteria

Every item is enforced; a failure at any point prints `DRILL_RESULT=FAIL` and a
specific reason. Checks are never skipped to make a run green.

### Manual mode

| # | Check | Threshold |
|---|---|---|
| 1 | `cluster_ready` | Every node logs `FINALIZED block #` and serves `eth_blockNumber >= 1` within `--ready-timeout`. All nodes report the **same** `chain epoch` fingerprint. |
| 2 | `height` | The minimum RPC height reaches `--min-height` (default 12). |
| 3 | `traffic_applied` | At least one submitted PQ transfer is finalized: faucet nonce strictly increases and at least one tx has a receipt with a `blockNumber`. |
| 4 | `pre_stop_consistency` | At the common pre-stop height `H`, every node serves the same durable block hash and the same QC-anchored historical root (state after `H-1`). |
| 5 | `graceful_stop` | Every node exits **0** after SIGTERM within `--stop-timeout`; each log contains `persistence drained; exiting` and **not** `shutdown drain cap reached`. |
| 6 | `binary_swap` | The live `ExecStart` path (one atomically replaced file) has the new SHA-256; every restarted process' `/proc/<pid>/exe` is that file and `/proc/<pid>/environ` carries the new `STELL_UPGRADE_VERSION` label. |
| 7 | `resumed` | At least one node finalizes a block **above** `H` within `--resume-timeout`; then **all** nodes finalize above `H`. |
| 8 | `historical_integrity` | Re-querying height `H` after restart returns the same durable block hash and the same QC-anchored historical root. A change is a reorg or a double-apply. |
| 9 | `no_double_apply` | The faucet balance and nonce are **exactly** unchanged across the restart (no new traffic is sent after restart). |
| 10 | `state_root_consistency` | At the common post-restart height `P > H`, all nodes serve the same durable block hash and the same QC-anchored root (state after `P-1`). |
| 11 | `integrity_counters` | Per node, `stell_divergence_total`, `stell_fork_total`, `stell_weak_qc_refused_total`, `stell_persist_queue_dropped_total` do not increase from the pre-stop value. |
| 12 | `rto_budget` | `RTO <= --rto-budget-seconds` (default 180 s). |
| 13 | `marker_absent` | Manual mode must not create `data/upgrade-halt.marker`. |

**RTO definition (manual):** `first SIGTERM` → `first FINALIZED block with
height > pre-stop height on any node`. It includes the graceful drain, the
binary install, process startup, and catch-up to the first new block.

### On-chain mode (when the gate is open)

| # | Check |
|---|---|
| 1 | `UPGRADE_EXEC_ACTIVATION_HEIGHT` is finite (not `u64::MAX`). Otherwise exit 1 before starting anything. |
| 2 | `--plan-name` is a safe single path segment; `--plan-height > 0`; `--staged-bin` and `--submit-cmd` are executable; staged SHA-256 is computed. |
| 3 | The cluster reaches `--min-height`; `--plan-height` is at least 10 blocks above the current tip. |
| 4 | The submitter exits 0, but the drill does **not** trust that: the halt marker must prove the executed plan's exact `(name, height, sha256)` and every node must exit 42. |
| 5 | Every node exits **42** when the plan height is reached. Any other code fails the drill. |
| 6 | Every node has `data/upgrade-halt.marker` with header `stell-upgrade-halt v1`, `height == plan_height`, `plan_name`, `plan_sha256` matching the staged binary, `target_version`, and `halted_at_height >= plan_height`. |
| 7 | Each log contains `halt marker written` and `persistence drained`; `halt drain CAP reached` fails the drill. |
| 8 | Restarting the **old** binary against the marker exits non-zero and logs `REFUSING TO START CONSENSUS` on every node (fail-closed guard). |
| 9 | Installing the staged binary at the live path and restarting clears the marker on every node and finalizes above the halt height. |
| 10 | The pre-halt height's durable block hash and QC-anchored root are unchanged after the upgrade. |
| 11 | All nodes agree on a common post-upgrade height and root. |
| 12 | RTO (first halt exit → first new finalized block) is reported; it is not currently budget-gated in on-chain mode. |

---

## 5. Interpreting a failure

The failing check and a specific reason are printed before the summary. Start
with `$RUN_ROOT/node<i>/live.log`.

| Symptom / reason | Meaning | First action |
|---|---|---|
| `cluster did not become ready` | Peers cannot hear each other, consensus does not start, or genesis split. | Check the node logs for `genesis state root mismatch`, `topic`, or `wrong proposer`; verify `chain epoch` is identical. Do **not** edit the chain id to "fix" it. |
| `genesis epoch split at startup` | The three nodes derived different genesis inputs (validator set, faucet key, PQ mapping, or code constants). | Diff `validators:`, `STELL_PEER_PQ_KEYS`, `STELL_FAUCET_KEY`, and `STELL_LEGACY_GENESIS_ROOT` across the node configs. |
| `traffic was accepted but no transfer was finalized` | Mempool admission worked but blocks did not include the tx (or the nonce/receipt path is wrong). | Check `FINALIZED block #` is advancing; check the tx receipt and mempool logs. |
| `nodeX exited N on SIGTERM (expected 0)` | The shutdown handler did not complete; the RPO is unproven. | Look for a panic/drain error in that log. This is a real failure, not a reason to SIGKILL. |
| `hit the persistence drain cap` | The writer was wedged or the disk could not drain. | Treat as an RPO failure; inspect storage errors. |
| `did not log 'persistence drained; exiting'` | The graceful path was bypassed (e.g. the process died before the handler). | Check the exit code and the log tail. |
| `runs '<path>', expected '<live path>'` | The new image was not the one actually executed. | Check the swap/`ExecStart` path; the drill does not accept a version string alone. |
| `reports STELL_UPGRADE_VERSION='...', expected '...'` | The restarted process is the old label. | The supervisor/unit environment is stale; fix the deployment, do not weaken the check. |
| `block H changed hash after restart` | Reorg or nondeterministic re-execution at/above `H`. | Preserve all data dirs. Compare the node logs around `H`; check commitment/snapshot versions. After a state-affecting gate, rollback is not supported (see `UPGRADE_AND_RECOVERY.md` §1.7). |
| `state root ... changed after restart` | Same as above, at the state-root level. | Do not restart more nodes until the divergent one is understood. |
| `faucet nonce changed across restart` | A finalized transfer was re-applied from a replayed mempool/queue. | Inspect mempool persistence and the admission nonce gate; this is the double-apply the drill exists to catch. |
| `header split at height` / `state-root split` | Two nodes disagree on finalized history. | Check identity keys, genesis epoch, and the last common height. A real fork is a stop-the-world event. |
| `stell_divergence_total grew` (or fork/weak-QC/dropped-persist) | A safety counter moved during the upgrade. | Preserve logs and data; do not proceed to a second node. |
| `RTO ... exceeds budget` | The outage exceeded the operator budget. | Read the per-phase timings (drain, startup, catch-up); `--rto-budget-seconds` is a policy input, not a target to game. |
| `cannot prove block/root at height H from its durable store` | The header/body/QC for the check height was pruned, or the node did not persist it. | Run with archive retention (the default); do not lower retention for the drill. |
| `upgrade-halt.marker` mismatch (on-chain) | The halt fired with a different plan than the one submitted. | Compare the marker fields with `--plan-name/--plan-height/--staged-bin`; the plan binding is by name+height+sha. |
| `OLD binary started successfully despite the halt marker` | The startup guard failed open. | Stop immediately; do not put this binary on a live node. Preserve the data dir and marker. |

---

## 6. What the drill does not cover (known gaps)

These are deliberate, explicit gaps — not "skipped checks". Do not cite a PASS
as evidence for anything in this list.

1. **On-chain execution is gated.** `UPGRADE_EXEC_ACTIVATION_HEIGHT =
   u64::MAX` in this tree, so a passed `SoftwareUpgrade` never installs
   `upgrade_plan`. The on-chain mode therefore exits 1 with a clear message and
   starts no cluster. The gate-open orchestration is written, but **untested**;
   it requires an operator-supplied `--submit-cmd` because this tree has no CLI
   that builds and PQ-signs a `SysCallGovPropose` transaction.
2. **Governance timing is not shortened.** `GOVERNANCE_VOTING_PERIOD_SECS` is
   3 days and `GOV_TIMELOCK_HEIGHTS` is 7,200. A real gate-open run needs a
   harness/debug path that can drive a proposal through those windows; the
   drill does not edit the constants (that would be a different binary and a
   fork risk) and does not use the fork-prone multi-node direct-RPC form.
3. **Snapshot-1100 vs body-walk-256 recovery deadlock.** The manual drill
   restarts from the **local data directory**, not from a snapshot. It does not
   exercise a node that lost its store and must restore a snapshot at `B` and
   walk `B+1..F`. The hard case in `UPGRADE_AND_RECOVERY.md` §1.6 — consecutive
   snapshots up to `snap_int + 100 = 1100` apart while the body walk refuses
   more than `256` blocks on a halted chain — remains unproven by this drill.
4. **Mixed-version rolling upgrade until UP-1 lands.** This is a
   **full-cluster stop/swap/restart** drill, not a rolling upgrade. With
   `FRAME_VERSION` exact-match `2` and no negotiation, mixed old/new nodes
   cannot talk; a one-node-at-a-time rollout would partition rather than prove
   compatibility. The drill does not test it. Do not use it as evidence that a
   rolling upgrade is safe.
5. **Same-tree copy by default.** The default "new" binary is a byte copy of
   the old one (plus a label/marker). That proves the swap, drain, marker, and
   restart machinery but **not** that a different build implements the same
   state semantics. Pass `--new-binary /path/to/really-rebuilt/stellereum` to
   make the historical hash/root checks a real compatibility gate.
6. **`STELL_AUTO_UPGRADE` / in-place `execve` is not exercised.** The manual
   mode is the supervisor path. The on-chain mode (when open) uses the exit-42
   supervisor path by default. The question from
   `UPGRADE_AND_RECOVERY.md` §1.2.4 — whether sled's on-disk lock survives an
   `execve` while the handles are open — remains **UNVERIFIED**.
7. **Local loopback RTO is not WAN RTO.** No network latency, TLS, DHT fetch,
   or snapshot-blob transfer is exercised. The 10.8 s number is a floor for
   this host, not a production SLO.
8. **Consensus-id derivation is a tooling workaround.** `stellereum keys init`
   prints the PQ transport id (`id=inf1:…`) but `validators:`/`consensus-pub`
   are Ed-keyed (`blake3(ed_pub)[..20]`). The drill therefore derives the Ed
   public key with `wallet address`, hashes it with a tiny `rustc` + `blake3`
   helper, and refuses to guess if the helper cannot be built. This is a
   usability gap in the key tooling, not a chain problem; it is also why the
   drill needs `rustc` and an existing `libblake3` rlib.
9. **Three-node quorum is unanimous.** With `N=3`, stopping all three
   guarantees a halt; the drill measures planned full-cluster downtime, not
   failure detection, HA, or the `n=4` "one node down is survivable" behavior.
10. **No faucet/staking/governance stress.** The only traffic is a small PQ
    transfer. The drill does not exercise staking, validator rotation,
    governance besides the on-chain mode's submitter, or a large mempool.
11. **Artifacts are kept by default.** Data directories and logs live under
    `/tmp/opencode/upgrade-drill-*`; use `--purge-on-pass` to remove them. A
    failed run always keeps them for diagnosis.

---

## 7. Safety properties of the script

* **`--local-only` is required.** No flag, no run.
* Every generated `listen`/`advertise`/`endpoints` address is audited and must
  be loopback or RFC1918, or the script aborts.
* Every port is allocated dynamically, checked free with a real bind, and the
  documented live bases are rejected even if free.
* Every data dir, key dir, log, binary copy, and summary is under
  `/tmp/opencode/upgrade-drill-<timestamp>-<pid>/`.
* The live cluster (`multinode/nodeB`, ports `18645+i` / `18080+i` /
  `19410+i`) is never addressed. No faucet, staking, or governance RPC is sent
  to anything except the ports this run allocated; the only governance-adjacent
  call in manual mode is a plain PQ transfer used as traffic.
* Every process this script starts is tracked by PID and killed by an
  `EXIT`/`INT`/`TERM` trap. It never uses `pkill stellereum` or any
  pattern-wide kill.
* A mode that cannot work fails loudly. There are no `todo!()`/placeholder
  branches: the gated on-chain mode exits 1 with the gate reason, and the
  gate-open path requires its explicit inputs or fails before starting a
  cluster.

---

## 8. Reproducing the recorded result

```bash
cd /path/to/stellereum-project
CARGO_BUILD_JOBS=2 cargo build -p stellereum
./scripts/upgrade_drill.sh --mode manual --local-only --nodes 3
```

Recorded 2026-11-19:

| Field | Value |
|---|---|
| Result | **PASS** |
| Nodes | 3 |
| Pre-stop height | 19 |
| Post-restart common height | 65 |
| Measured RTO | **10.812 s** (`rto_ms=10812`) |
| Old/new label | `drill-old-bb6210e9` / `drill-new-bb6210e9` |
| Historical block 19 | unchanged (hash and QC-anchored state root) |
| Faucet nonce/balance across restart | unchanged |
| Integrity counters | flat on every node |
| Run dir | `/tmp/opencode/upgrade-drill-20261119-102547-2016350` |

The 1-node fallback was also run: **PASS**, RTO **10.707 s**, heights 21 → 84.
