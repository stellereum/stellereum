# CI

Two GitHub Actions workflows gate this repository:

| Workflow | File | Trigger | What it is |
|---|---|---|---|
| `CI` | `.github/workflows/ci.yml` | every `pull_request`; push to `main` and `full-pq-testnet-*` | the fast PR gate (curated) |
| `Nightly full gate` | `.github/workflows/nightly.yml` | daily at `02:00 UTC`; manual `workflow_dispatch` | the **authoritative** full test run |

They only check out, install the pinned toolchain, build, and test. They use no
secrets, no deploy target, no live cluster, no faucet, and no external service
beyond the Cargo/npm registries needed to install the pinned dependencies.
Tests that need a server use loopback (`127.0.0.1:0`) mocks.

## Job graph

Every job is independent (no `needs:`), so a PR run is a flat fan-out. A
failure in one job does not suppress the others (`fail-fast: false` on the
matrices), which keeps the red signal specific.

```
CI (pull_request / push)
├── fmt              timeout 10m   rustfmt, three workspaces, one job
├── clippy           timeout 45m   matrix: stellereum | infnode
├── test-lib         timeout 45m   cargo test --lib, stellereum + infnode
├── test-suites      timeout 60m   matrix: consensus | state | rpc |
│                                  compact | sync | xshard
├── sdk              timeout 30m   stellereum-sdk (Rust) + sdk-js (Node 22)
└── loadtest-build   timeout 25m   scripts/loadtest/loadtest

Nightly full gate (cron / manual)
└── full-gate        timeout 240m  scripts/test_parallel.sh -p stellereum
                                   JOBS=3, TEST_THREADS=2, log artifact
```

The PR workflow cancels a superseded run for the same PR/branch
(`concurrency.cancel-in-progress: true`). The nightly deliberately does **not**
cancel: a full gate is expensive and its log is the audit record.

## The curated PR suites

`test-suites` is a six-leg matrix. Each leg runs only the listed integration
binaries, with `--test-threads=2` and `CARGO_BUILD_JOBS=2`. The same list is
implemented in `scripts/ci_local.sh`; keep the two in sync.

| Leg | Test binaries |
|---|---|
| `consensus` | `consensus_liveness_harness`, `consensus_byzantine_tests`, `consensus_security_tests`, `bft_lock_safety_tests`, `liveness_horizon_tests`, `sim_tempo_target06_tests` |
| `state` | `state_root_completeness_tests`, `state_commit_batch_tests`, `apply_floor_tests`, `parallel_apply_parity_tests`, `block_packing_scale_tests` |
| `rpc` | `rpc_tests`, `rpc_batch_tests`, `rpc_ws_tests`, `rpc_surface_audit_tests` |
| `compact` | `compact_gossip_tests`, `pentest2_network_compact` |
| `sync` | `sync_adversarial_tests`, `sync_walk_concurrency_tests`, `catch_up_tests`, `epoch_sync_tests` |
| `xshard` | `xshard_2pc_tests`, `xshard_replay_tests`, `cross_shard_e2e_pq_tests`, `cross_shard_anchor_tests` |

The full workspace has ~335 test harnesses. The PR gate runs 25 of them plus
the lib tests; it is a smoke gate for the expensive paths, not a substitute for
the nightly. The three slowest binaries (`block_packing_scale_tests`,
`liveness_horizon_tests`, `sim_tempo_target06_tests`) are included on purpose:
they are the ones that catch packing, horizon, and tempo regressions, and the
matrix keeps their wall time off the fast legs.

### Relationship to the older scripts

`scripts/test_parallel.sh` is the engine the nightly invokes; it builds every
test target with cargo and then runs the resulting harnesses concurrently, one
binary per worker slot. `scripts/nightly_gate.sh` is an older five-stage QA
cron (clippy, lib, fuzz battery, feature matrix, audit-repro) and is **not**
wired into these workflows; it remains a manual/ops script. The old
`scripts/nightly_ci_notes.md` predates `.github/` and is historical.

## PR gate vs nightly full gate

| | PR gate (`ci.yml`) | Nightly (`nightly.yml`) |
|---|---|---|
| Test scope | lib + 25 curated binaries | **every** test binary (~335) |
| Parallelism | one cargo process per matrix leg | `test_parallel.sh`, 3 binaries at once |
| Threads per binary | 2 | 2 |
| Build jobs | 2 | 2 |
| Duration | tens of minutes cold | ~1.5–2 hours cold (see below) |
| Artifacts | normal Actions logs | full `nightly.log` + per-binary logs, 14 days |
| When red | blocks the PR | the authoritative "is the tree actually green" answer |

`consensus_liveness_harness` is in the PR `consensus` leg because it is the
deterministic 4-node simulator, not because it is cheap. Its 30-virtual-second
report variant is `#[ignore]`d on purpose and is run manually:

```sh
cd stellereum
cargo test --test consensus_liveness_harness -- --ignored --nocapture
```

## Reproduce a red job locally

One command for the PR gate:

```sh
scripts/ci_local.sh
```

That runs `fmt`, `clippy` (both workspaces), `test-lib` (both workspaces), and
all six curated suites, printing per-command and per-stage timings. The last
line is machine-readable:

```
CI_LOCAL_RESULT=PASS total_seconds=1234 passed=4 failed=0
```

Other modes:

```sh
scripts/ci_local.sh --full          # the nightly gate: all binaries via test_parallel.sh
scripts/ci_local.sh --suite xshard  # one curated leg, e.g. to debug a red matrix job
scripts/ci_local.sh --sdk           # Rust SDK + sdk-js (if node_modules exists)
scripts/ci_local.sh --loadtest      # build the load-test harness
JOBS=8 TEST_THREADS=4 scripts/ci_local.sh --full
```

`JOBS` controls how many test binaries run at once; `TEST_THREADS` controls
threads inside one binary; `CARGO_BUILD_JOBS` controls rustc jobs. The defaults
are deliberately conservative (`JOBS=2` for the PR gate, `JOBS=3` for
`--full`, `TEST_THREADS=2`, `CARGO_BUILD_JOBS=2`) to match a 4 GB GitHub
runner. Raise them on a workstation.

`scripts/ci_local.sh` performs no downloads and exports
`CARGO_NET_OFFLINE=true`. On a fresh clone, warm the Cargo caches once:

```sh
(cd stellereum && cargo fetch)
(cd infnode && cargo fetch)
(cd stellereum-sdk && cargo fetch)
(cd scripts/loadtest/loadtest && cargo fetch)
```

Then the gate is offline. (`--sdk` additionally needs `sdk-js/node_modules`;
run `npm ci` in `sdk-js` once, which needs network. Without it the JS stage is
reported as skipped, not failed.)

### Exact per-job commands

Run these from the repository root to reproduce one CI job without the helper:

```sh
# fmt
(cd stellereum && cargo fmt --all --check)
(cd infnode && cargo fmt --all --check)
(cd stellereum-sdk && cargo fmt --all --check)

# clippy
(cd stellereum && cargo clippy --locked --all-targets -- -D warnings)
(cd infnode && cargo clippy --locked --all-targets -- -D warnings)

# test-lib
# The stellereum lib suite MUST run one test per thread: several consensus
# tests replace the PROCESS-GLOBAL committed PQ registry
# (`consensus::sync_committed_pq_registry`), so parallel execution makes one
# test erase another test's validator keys and fails as
# "bad vote signature" / "invalid proposer signature". `cargo nextest` is safe
# because it runs every test in its own process; plain `cargo test` needs
# `--test-threads=1` (see docs/CI.md § "Why the lib suite is serial").
(cd stellereum && cargo test --locked --lib -- --test-threads=1)
(cd infnode && cargo test --locked --lib -- --test-threads=2)

# one curated suite leg, e.g. consensus
(cd stellereum && cargo test --locked --test consensus_liveness_harness -- --test-threads=2)
(cd stellereum && cargo test --locked --test consensus_byzantine_tests -- --test-threads=2)
(cd stellereum && cargo test --locked --test consensus_security_tests -- --test-threads=2)
(cd stellereum && cargo test --locked --test bft_lock_safety_tests -- --test-threads=2)
(cd stellereum && cargo test --locked --test liveness_horizon_tests -- --test-threads=2)
(cd stellereum && cargo test --locked --test sim_tempo_target06_tests -- --test-threads=2)

# sdk
(cd stellereum-sdk && cargo test --locked)
(cd sdk-js && npm ci && npm run typecheck && npm test && npm run build)

# loadtest
(cd scripts/loadtest/loadtest && cargo build --locked)

# nightly authoritative gate
JOBS=3 TEST_THREADS=2 scripts/test_parallel.sh -p stellereum
```

The workflows use `dtolnay/rust-toolchain@stable` with `rustfmt` and `clippy`.
To match locally, install the same components:

```sh
rustup toolchain install stable --component rustfmt --component clippy
rustc -V
```

## Why the lib suite is serial

`stellereum` keeps the validator post-quantum key registry in **process-global**
statics (`consensus::rotation::{PQ_VALIDATOR_KEYS, PQ_COMMITTED_REGISTRY}`).
Production is correct that way: the live node has exactly one committed
registry per process.

Tests are not that shape. Several suites build their own 4-node fixture and
call `consensus::sync_committed_pq_registry(&reg, true)`, which **replaces** the
global registry (by design — it mirrors the on-chain registry at the current
height). If two such tests run at the same time, one wipes the other's
validator keys and an **unrelated** test fails with:

```text
vote admits: "bad vote signature"
proposal: "invalid or missing proposer signature"
bridge quorum: no committed PQ key at attestation height
```

Those failures are 100 % reproducible as a function of scheduling: the same
tests pass with `--test-threads=1`. The fix is isolation, never a weaker
assertion. Two safe ways to run:

```sh
# every test in its own process (preferred when installed)
cargo nextest run --lib

# plain cargo: serialize the tests that own the global registry
cargo test --lib -- --test-threads=1
```

The `bin` target keeps its parallelism because the affected tests there take
the shared `crate::node::policy::test_support::global_lock()` guard.

## Expected durations

These are engineering estimates for a GitHub-hosted Linux runner with 4 GB
RAM, not measurements of this workflow. Caches are cold on the first run and
warm afterwards. `Swatinem/rust-cache@v2` caches `~/.cargo` and each workspace
`target/`.

| Job | Cold | Warm | Critical path note |
|---|---|---|---|
| `fmt` | 1–2 min | 1 min | no compile |
| `clippy` (node) | 12–25 min | 3–6 min | `--all-targets` is the expensive one |
| `clippy` (infnode) | 5–10 min | 2–4 min | runs in parallel with node |
| `test-lib` | 8–15 min | 3–6 min | builds the node lib once |
| `test-suites` (per leg) | 15–40 min | 5–15 min | six legs run in parallel; consensus/state carry the long binaries |
| `sdk` | 4–8 min | 2–4 min | Rust SDK + `npm ci` + sdk-js |
| `loadtest-build` | 5–12 min | 2–4 min | standalone crate |
| **PR wall time** | **~35–50 min** | **~15–25 min** | slowest matrix leg wins |
| **Nightly wall time** | **~75–120 min** | **~50–90 min** | build all targets, then 3 at a time |

Evidence from the last local full run (2026-11-19, not a GitHub runner):

- build of the test profile: 15m 08s;
- 346 harness logs, 4,204 tests passed, 0 failed, 2 ignored;
- ~2,247 s of summed per-binary test time (the sum, not the wall time);
- slowest single binary: `block_packing_scale_tests` at 374.69 s;
  `liveness_horizon_tests` at 343.66 s; `sim_tempo_target06_tests` at 277.06 s
  (all three are in the PR matrix now).

With `JOBS=3`, the run time is bounded below by those long binaries; a 4 GB
runner is slower than the workstation that produced the numbers above. The
six matrix legs each compile the dependency graph independently, so their
total CPU cost is higher than one sequential run; the wall time is lower
because the legs run concurrently. The nightly job timeout is 240 minutes,
with a 210-minute step timeout so the log upload still runs if the gate
overruns.

## Known limits

- **No hardware-in-the-loop.** CI has no HSM, no hardware wallet, no TPM, no
  remote signer appliance, and no real network impairment. Those stay manual.
- **No external audit.** CI proves the checked-in tests pass. It does not
  replace a third-party cryptography/consensus audit, and it does not run
  `cargo fuzz` (the libFuzzer targets need a nightly toolchain and are manual;
  the deterministic `fuzz_economics_ext` binary is the only fuzz-shaped test in
  the gate).
- **The nightly is the only ~335-binary run.** PR CI intentionally runs 25
  integration binaries. A green PR does not mean every integration suite is
  green.
- **No live cluster, faucet, deploy, or secrets.** Anything that needs a
  running testnet, funded accounts, or key material is out of scope.
- **Two tests are ignored on purpose**, so neither gate runs them:
  `consensus_liveness_harness::slow_variant_thirty_virtual_seconds_prints_a_report`
  (manual diagnostic report) and
  `hunt_f3f4f5_verify::f5_open_current_quorum_rewrites_old_heights`
  (documents a test-only compatibility limitation). They are not failures.
- **Single host, loopback only.** Tests may bind `127.0.0.1:0`, but there is no
  multi-host WAN, packet loss, partition, or clock-skew test in CI. Matrix legs
  run on separate runners, so fixed ports within a binary are the only local
  contention risk.
- **Runner memory is 4 GB.** `CARGO_BUILD_JOBS=2` and `TEST_THREADS=2` are
  safety limits, not tuning suggestions. Raising them on a hosted runner can
  OOM the linker.
- **Disk is the other hosted-runner limit.** A local `stellereum/target` is
  ~27 GB, of which ~5 GB is test executables (measured 2026-11-19). See
  *Disk budget and target cleanup* below for the per-directory numbers and the
  `scripts/clean_target.sh` workflow. The nightly removes preinstalled
  .NET/Android/GHC/CodeQL trees before building to make room. If a future tree
  outgrows that, split the nightly by test group or use a larger runner; a
  single 14 GB runner will not hold every target plus a full cargo cache.
- **A hung test binary is bounded only by the job/step timeout.** The nightly
  uploads the per-binary log directory on `always()`, but a killed step cannot
  flush a log for the binary that never returned.
- **Caches are not build outputs.** A cache restore makes a run faster; it is
  not a correctness input. If a job is red only on a cold cache, suspect a
  missing dependency or a stale lockfile, not the cache.
- **The `fmt` command follows path dependencies.** `cargo fmt --all` in
  `stellereum` visits the `infnode` sources it links, so an `infnode` formatting
  problem can surface in the `stellereum` invocation as well. Fix it at the
  source.

## What must change to make this gate green

At authoring time the workflows have been syntax-validated but **not executed
on GitHub**. The following are the concrete repo-side items that can turn the
new gate red:

1. **Rustfmt drift in `infnode`.** `cargo fmt --all --check` reported diffs in
   `infnode/crates/infnode/src/dht.rs` and `.../src/node.rs` (active edits in
   the tree). **Resolved 2026-11-19 for those two files** (CI-1); the `fmt`
   job can still fail on files owned by other agents — see *Remaining rustfmt
   drift* below.
2. **The `loadtest` crate is not rustfmt-clean** (`src/main.rs` assert
   wrapping). This does not fail the gate because the workflow only builds it;
   if formatting is added to `loadtest-build` later, format it first.
   **Resolved 2026-11-19** (CI-1): `scripts/loadtest/loadtest/src/main.rs` is
   now rustfmt-clean.
3. **`--locked` everywhere.** The node, infnode, SDK, and loadtest jobs use
   `--locked`. If a `Cargo.toml` changes without a matching `Cargo.lock`,
   CI fails early with "the lock file needs to be updated". Update the lock in
   the same change. **Verified 2026-11-19** (CI-1): all four gated lockfiles
   resolve under `--locked`; no regeneration was needed.
4. **Node version for `sdk-js`.** The `sdk` job uses `actions/setup-node@v4`
   with Node 22 and `NODE_OPTIONS=--experimental-strip-types`, because the
   tests execute `.ts` directly. Node 22.18+ enables type stripping by default;
   the flag keeps 22.6–22.17 working.
5. **No known flaky binary at the last full local snapshot.** The 2026-11-19
   run was 4,204 passed / 0 failed / 2 ignored, so there is no test to
   quarantine today. The tree has uncommitted, in-progress source edits; the
   gate can only be as green as the commit that triggers it. Re-run the
   relevant `--suite` or `--full` after those edits land.
6. **Branch protection.** If you require checks, require the PR job names
   (`fmt`, `clippy (stellereum)`, `clippy (infnode)`, `test-lib`,
   `test-suites (consensus)` … `test-suites (xshard)`, `sdk`,
   `loadtest-build`) or a subset; the nightly is not a PR check.

### CI-1 status (2026-11-19)

Items 1 and 2 above are **resolved** for the files CI-1 owns:
`infnode/crates/infnode/src/dht.rs`, `infnode/crates/infnode/src/node.rs`, and
`scripts/loadtest/loadtest/src/main.rs` are now rustfmt-clean under
`rustfmt --edition 2021 --check`. `cargo fmt --all --check` still reports
drift in other files that other agents are actively editing; those are listed
per file below and were deliberately **not** reformatted here.

Item 3 is **verified**: all four lockfiles resolve under
`cargo metadata --locked --offline --filter-platform x86_64-unknown-linux-gnu`
with no regeneration, so the `--locked` jobs are not blocked by a stale lock.

### Remaining rustfmt drift (not owned by CI-1)

`cargo fmt --all --check` in `stellereum` and `infnode` still fails on these
files, all with uncommitted edits in the tree (owner = the agent editing that
area):

- `stellereum/src/**`: `consensus/engine.rs`, `consensus/qc_split.rs`,
  `consensus/sortition.rs`, `consensus/tests/core.rs`,
  `consensus/tests/post_quantum_uqc_tests.rs`, `consensus_net.rs`, `lib.rs`,
  `network.rs`, `node/consensus_driver.rs`, `node/sync.rs`, `protocol.rs`,
  `runtime/anchors.rs`, `runtime/consensus_step.rs`, `runtime/tests/mod.rs`,
  `state_engine/contracts.rs`, `xshard2pc.rs` — owner: the `stellereum/src/**`
  agents.
- `stellereum/tests/**`: `compact_gossip_tests.rs`, `mmr_epoch_root_tests.rs`,
  `pentest2_consensus_loopback.rs`, `pentest2_network_compact.rs`,
  `pentest2_network_hardening.rs`, `protocol_mixed_cluster_tests.rs`,
  `protocol_negotiation_tests.rs`, `rpc_receipt_params_tests.rs`,
  `rpc_surface_audit_tests.rs`, `slashing_rotation_tests.rs`,
  `upgrade_exec_gate_tests.rs`, `upgrade_halt_tests.rs`,
  `validator_mesh_tests.rs`, `xshard_2pc_tests.rs` — owner: the test-suite
  agents.
- `infnode/crates/infnode/src/proto.rs` and
  `infnode/crates/infnode/tests/{dht_scale_tests,peer_eviction_tests,protocol_negotiation_tests,storage_seal_tests}.rs`
  — owner: the `infnode` agents.

Re-run `cargo fmt --all` in each workspace once those edits land; the `fmt`
job is red until then.

## Disk budget and target cleanup

Measured 2026-11-19 on the ops host (`du -sh` per directory, `df -B1`):

| Path | Size |
|---|---|
| `stellereum/target` | 27 GB |
| `target/debug` | 26 GB |
| `target/debug/incremental` | 17 GB (1,189 crate units) |
| `target/debug/deps` | 8.5 GB |
| `target/debug/build` | 80 MB |
| `target/debug/examples` | 311 MB |
| `target/debug/.fingerprint` | 86 MB |
| `target/release` | 1.3 GB |
| free space on `/` | 4.26 GB of 233 GB (**99% used**) |

### Projected nightly need

The nightly builds **every** test binary (~335 harnesses) in the test profile,
which is exactly the build that produced the 26 GB `target/debug` tree above.
`target/release` must stay (it holds the operator binaries), so the target
directory alone needs ~27 GB.

- **Cold build** (new/reclaimed target, or after `--aggressive`): ~27 GB of
  artifacts plus ~5 GB transient headroom for linker temporaries, per-binary
  logs and the uploaded `nightly.log` → reserve **~32 GB free**.
- **Warm build** (deps present, same lockfile, only workspace/test crates
  changed): ~8–12 GB free is enough for the rebuilt objects and new binaries.

Cargo fails mid-link when the filesystem is 100% full, so never start the gate
below ~5 GB free even in the warm case. The GitHub runner has its own 14 GB
budget and removes preinstalled toolchains; the numbers above are for the ops
host and any self-hosted runner with a persistent `target/`.

### `scripts/clean_target.sh`

Safe by default: it prints the plan and deletes nothing unless `--yes` is
given. It never touches `target/release`, never removes the `target/` root,
preserves `target/debug/deps` unless `--aggressive` is passed, and refuses a
destructive run while `cargo`/`rustc` is active (override with `--force` only
when those builds are unrelated).

```sh
scripts/clean_target.sh                      # dry run (default) — prints what would go
scripts/clean_target.sh --yes                # remove debug/incremental only
scripts/clean_target.sh --yes --aggressive   # also deps, build, examples, .fingerprint
scripts/clean_target.sh --target-dir infnode/target --yes
```

| Mode | Frees (measured) | Next build cost |
|---|---|---|
| `--yes` (default policy) | ~17 GB (`debug/incremental`) | recompiles workspace crates only; deps stay warm |
| `--yes --aggressive` | ~25–26 GB (adds `debug/deps`) | full dependency rebuild (~15 min on this host) |

Recommended nightly step: run the **dry run** first, then `--yes` when no
cargo/rustc is building. On the measured host, the default cleanup takes free
space from 4.26 GB to ~21 GB (enough for a warm nightly); a cold nightly needs
`--aggressive` or a larger volume.

## Historical scripts

These predate the GitHub workflows and are retained for reference. They are
**not** wired into CI and their behaviour is unchanged; a banner at the top of
each file points here.

| Path | Status | Superseded by |
|---|---|---|
| `scripts/nightly_gate.sh` | historical five-stage cron gate (clippy, lib, fuzz, feature matrix, audit-repro) | `.github/workflows/nightly.yml`; local equivalent is `scripts/test_parallel.sh` |
| `scripts/nightly_ci_notes.md` | historical note written before `.github/` existed | `.github/workflows/nightly.yml` and this document |

Do not add new stages to `scripts/nightly_gate.sh`. Extend
`.github/workflows/nightly.yml` (and mirror cheap legs in `ci.yml`) instead.
