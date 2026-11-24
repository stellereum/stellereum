# PERF_MATRIX — throughput/latency matrix, evidence rules

This document defines the **only** numbers the matrix harness is allowed to
publish, where each one comes from, and how to compare two commits without
lying to yourself. It contains **no measurements**: the first published matrix
must come from a real run of `scripts/perf-matrix.sh` with its raw cells kept.

Entry point: [`scripts/perf-matrix.sh`](../scripts/perf-matrix.sh)
Metric helper: [`scripts/loadtest/metrics-delta.awk`](../scripts/loadtest/metrics-delta.awk)
Load generator: [`scripts/loadtest/README.md`](../scripts/loadtest/README.md)

---

## 1. What the matrix is

One **cell** is one offer rate against one provisioned cluster:

```
validator count N  ×  offered tx/s  ×  block floor STELL_MIN_BLOCK_MS
```

Defaults: `N ∈ {4, 32, 128}`, `offered ∈ {100, 1000, 5000}`, floor `∈ {400, 250}` ms.
That is 18 canonical rows. A single machine can usually provision only one
`(N, floor)` pair, so one invocation measures one cluster's rates; run it again
against another cluster into the same results directory (`--reuse`) to fill more
rows. Rows with no cluster are rendered `NOT MEASURED` with a reason. They are
never interpolated, extrapolated, or copied from another row.

A cell is run **alone**: cells are strictly sequential, and a settle window
(height advancing, mempool back to zero) separates them. Two matrix processes
are prevented from sharing a results directory by an `flock`.

### Cell states

| state | meaning |
|---|---|
| `measured` | harness exited 0 (PASS) and a JSON report exists |
| `measured (FAIL)` | the wave ran, but the harness verdict was FAIL (rejections or backlog) |
| `**INVALID** (429)` | 429 share exceeded `--max-429-share`; throughput is not a capacity measurement |
| `ABORTED` | a harness stop condition fired (stall / node lag / backlog) |
| `TIMEOUT` | the hard per-cell `timeout` fired |
| `BLOCKED` | the harness refused (safety/usage/preflight funding) |
| `FAILED` | exit code or missing report; inspect the cell log |
| `NOT MEASURED` | no cell exists; the reason is in the row |

A failed, invalid or aborted cell is a **valid result**. It stays in the table.

---

## 2. Metric dictionary

Every row is derived from one of two files written during that cell:

* `cells/<id>/report.json` — the harness's own JSON report;
* `cells/<id>/metrics-delta.json` — the difference between two scrapes of the
  node's Prometheus endpoint (`stellereum/src/metrics.rs`), produced by
  `scripts/loadtest/metrics-delta.awk`.

| column | exact source | meaning | caveat |
|---|---|---|---|
| offered tx/s | `--rate` | target accepted submissions per second | it is an offer, not an achievement |
| accepted tx/s | `report.json` → `rates.accepted_tps` | RPC/mempool acceptance ÷ actual send window | **not execution**; duplicates count as accepted |
| included tx/s | `report.json` → `rates.included_tps` | on-chain nonce delta ÷ send window | authoritative "made it into blocks" count |
| apply p50/p95/p99 | `metrics-delta.json` → `apply.{p50,p95,p99}` | delta of `stell_apply_seconds` | bucket-interpolated; resolution is the bucket width; `>=x` means the quantile is in `+Inf` and is **censored** |
| confirm p50/p95/p99 | `report.json` → `confirmation_latency_s` | accepted submission → RPC nonce read shows it included | resolution is the harness poll cadence; **inclusion, not BFT finality** |
| block p50/p95 | `metrics-delta.json` → `block_interval.{p50,p95}`; fallback `report.json` → `block_time_s` | finalized block interval | node histogram when available, otherwise observed RPC arrival; the `src` field in `cell.json` records which |
| CPU s/block | `metrics-delta.json` → `cpu_per_block.mean`, fallback host `/proc` sum ÷ height delta | whole-process CPU per finalized block | node histogram is per-node; `/proc` fallback sums the listed PIDs and is labelled in the row notes |
| reverted sample | `report.json` → `receipt_sample.failed / queried` | share of sampled last-tx receipts that reverted | bounded sample (default 32), not a full receipt scan |
| rejected share | `report.json` → `rates.rejected_share` | terminal submission rejections ÷ (accepted+failed) | in `cell.json`, not a separate table column |
| 429 count | `report.json` → `counts.http_429` | rate-limit responses | a 429 storm makes the cell `INVALID` |

### Why confirmation latency was added to the harness

The pre-existing report measured acceptance, inclusion counts and block
timing, but not how long an accepted transaction waited. Each sender now keeps
`(nonce, accepted_at)` for its in-flight nonces and records the latency when a
nonce read shows `onchain > nonce`; the drain does the same for the tail. The
distribution is exported as `confirmation_latency_s` and printed as
`confirmation submit->nonce (s)`.

* It measures **RPC-observed inclusion**, not consensus finality.
* Its resolution is `--nonce-poll-ms` (during the window) or
  `--drain-poll-ms` (after it); a 250 ms / 1 s quantum is normal.
* A harness binary built before this field makes the matrix print
  `confirmation n/a (harness binary predates confirmation_latency_s)`.
  Rebuild with:
  ```bash
  cargo build --release --offline \
    --manifest-path scripts/loadtest/loadtest/Cargo.toml
  ```
  (`scripts/perf-matrix.sh --build` does the same.)

### Histogram quantiles are estimates

`metrics-delta.awk` subtracts bucket counts and linearly interpolates inside the
bucket containing the rank. The node's apply/CPU buckets are
`1, 5, 10, 25, 50, 100, 250, 500 ms, 1, 2.5, 5, 10 s`; a p99 that lands in
`+Inf` is printed as `>=10 s`, never as `10 s`. Do not compare a bucket estimate
to a microbenchmark as if they had the same precision.

The scrape window brackets the whole harness invocation, including its own
preflight and the one-second start delay. For a 60 s cell that is a small
dilution; for a very short `--duration` the idle portion dominates and the
apply/CPU/block columns are not representative. The histograms come from the
**one** node behind `--metrics-url`; they are not a cluster aggregate.

---

## 3. Running it

### 3.1 Provision and start a local cluster

Requirements: `bash` (4+), `jq`, `curl`, `awk`, GNU `timeout`, and optionally
`flock` (used to stop two matrix runs sharing a results directory). No new
Python/Rust dependency is introduced by the harness scripts.

`N` and the floor are properties of the **cluster**, not flags that mutate a
running node. The floor is `STELL_MIN_BLOCK_MS`; export it before boot so every
node inherits it.

```bash
cd /home/imm/stellereum-project
STELL_MIN_BLOCK_MS=400 ./scripts/local-cluster.sh up 4
```

`scripts/perf-matrix.sh --local-cluster` derives node 1's endpoints:
RPC `http://127.0.0.1:18646`, metrics `http://127.0.0.1:18081/metrics`, and the
node PIDs from `run/cluster/node*/node.pid`. It also reads
`/proc/<pid>/environ` and refuses a declared floor that disagrees with the
running nodes.

### 3.2 Fund the deterministic senders

The harness never funds accounts. Print the roster and fund it once from the
local faucet/treasury:

```bash
scripts/loadtest/loadtest/target/release/stell-loadtest \
  --allow-live --print-all-senders --url http://127.0.0.1:18646 --senders 128 \
  | tee /tmp/opencode/senders-128.txt
```

If the set is underfunded, the matrix writes `senders.txt`, records every cell
as BLOCKED, and exits 3. It does not run a half-funded wave.

### 3.3 Run the matrix

```bash
scripts/perf-matrix.sh \
  --local-cluster \
  --validators 4 \
  --block-floor-ms 400 \
  --i-know-this-is-not-mainnet \
  --rates 100,1000,5000 \
  --out run/perf-matrix/$(date -u +%Y%m%dT%H%M%SZ)
```

Add `--plan` to print the intended cells without touching the node.

A second cluster (for example an operator-provisioned 32-validator testnet)
fills more rows of the same results set:

```bash
scripts/perf-matrix.sh \
  --rpc http://testnet-rpc.internal:8545 \
  --metrics-url http://testnet-rpc.internal:8080/metrics \
  --validators 32 --block-floor-ms 250 \
  --i-know-this-is-not-mainnet --reuse \
  --out run/perf-matrix/20260101T000000Z
```

### 3.4 Guard rails

* The known public/validator hosts are refused by **literal** hostname match
  (no DNS resolution): `212.113.103.105`, `213.21.246.5`, `138.124.102.200`,
  `178.155.74.242`, `77.110.96.68`, `rpc.stellereum.org`.
* `--i-know-this-is-not-mainnet` is mandatory.
* A non-loopback endpoint requires `--allow-remote` (a test node, never
  production).
* `--rpc` is mandatory (or `--local-cluster`, which is an explicit choice).
* Every cell runs under `timeout --signal=INT --kill-after=30s`.
* The harness itself additionally refuses live traffic without `--allow-live`;
  the matrix never passes `--operator-order`, so the public path is closed
  twice.
* Cells run one at a time; the results directory is locked with `flock`.

### 3.5 Re-render without re-running

```bash
scripts/perf-matrix.sh --render-only run/perf-matrix/20260101T000000Z
```

The renderer only reads `meta.json` and `cells/*/cell.json`.

---

## 4. The published report

`summary.md` is the publishable artifact. Its shape:

```markdown
# Stellereum throughput/latency matrix

## How to reproduce
- Repo / commit (dirty state) / UTC date
- Host model, vCPUs, RAM, kernel
- Harness path + sha256
- RPC, metrics, declared floor (and whether it was verified)
- Exact invocation and per-cell commands (Appendix A)

## Provisioned clusters in this results set
| N | floor ms | RPC |

## Matrix
columns: N, floor ms, offered tx/s, senders, state, accepted tx/s,
included tx/s, apply p50/p95/p99 ms, confirm p50/p95/p99 ms,
block p50/p95 ms, CPU s/block, reverted sample, notes

## Metric provenance
## Between-cell hygiene
## Appendix A — exact per-cell commands
## Limits of this evidence
```

Raw evidence that must be archived with it:

```
meta.json
matrix.jsonl
cells/<id>/command.txt
cells/<id>/loadtest.log
cells/<id>/report.json
cells/<id>/metrics-before.txt
cells/<id>/metrics-after.txt
cells/<id>/metrics-delta.json
cells/<id>/cell.json
```

If a cell's evidence is missing, the row must be marked `NOT MEASURED`; do not
reconstruct it from memory or a neighbouring row.

---

## 5. Comparing two commits

The comparison is only valid **cell by cell**. `N=32 @ 250 ms @ 1000 tx/s` on
commit A is compared to the same cell on commit B, on the same host, with the
same sender count, duration and rate-limit configuration.

Protocol:

1. Run the matrix on commit A and B into separate results directories.
2. Use at least three repetitions per cell; publish the median of the three
   per-cell values, and keep all three raw cells.
3. Compare only cells where both sides are `measured` (not `INVALID`/`BLOCKED`)
   and neither side has a changed cluster shape (`N`, floor, senders, duration).
4. For censored values (`>=`), report both sides as censored. `>=10 s` versus
   `12 s` cannot be ordered.
5. Treat changes smaller than the run-to-run spread as noise. Derive that
   spread from the three repetitions, not from intuition.
6. Never compare a local single-host cluster to a distributed testnet and call
   the difference a code effect.

A minimal join recipe (both `matrix.jsonl` files are one JSON object per line):

```bash
cd run/perf-matrix/A && jq -r '[.id,.accepted_tps,.included_tps,.apply.p95,.confirmation.p95,.block.p95,.cpu_per_block]|@tsv' matrix.jsonl | sort > /tmp/opencode/A.tsv
cd ../B          && jq -r '[.id,.accepted_tps,.included_tps,.apply.p95,.confirmation.p95,.block.p95,.cpu_per_block]|@tsv' matrix.jsonl | sort > /tmp/opencode/B.tsv
join -t $'\t' /tmp/opencode/A.tsv /tmp/opencode/B.tsv
```

The joined columns are `id, A_accepted, A_included, A_apply_p95, A_confirm_p95,
A_block_p95, A_cpu, B_accepted, ...`. State the commit hashes beside them.

---

## 6. Honest limits (read before quoting a number)

1. **A 4-validator, empty chain proves nothing about N=128.** Consensus
   message count, quadratic vote/QC verification, fan-out and CPU contention
   all change with N. The matrix renders N=32/128 as `NOT MEASURED` unless a
   real cluster of that size was provisioned and its RPC reported that
   validator count.
2. **One machine cannot honestly host 128 validators** for a throughput claim:
   the load generator, the validators and the metrics endpoint compete for the
   same cores. Such a run measures the host, not the protocol.
3. **The sender set can be the bottleneck.** With 128 senders and a measured
   ~2 tx/s per sender on a WAN, ~256 tx/s is the ceiling; a 5,000 tx/s row will
   show a low accepted rate that says nothing about the node. The report flags
   any cell below 75% of the offer, but cannot distinguish sender-bound from
   node-bound without a sender sweep.
4. **The RPC rate limiter can invalidate a cell.** The default standalone
   budget is `STELL_STANDALONE_RATE_LIMIT` = 300 requests/s per IP. A cell above
   that from one IP will produce 429s; the matrix marks it `INVALID` when the
   429 share exceeds `--max-429-share` (default 1%). Raising the limiter
   requires a node restart and is outside the matrix.
5. **Apply/CPU/block percentiles need `/metrics`.** Without it those columns are
   `n/a`; the report does not substitute a guess. The `/proc` CPU fallback is
   labelled and covers only the listed PIDs.
6. **Confirmation is not finality.** `confirmation_latency_s` stops at the RPC
   nonce read. It says nothing about BFT finalization time, view changes, or
   cross-node agreement.
7. **The failed share is a sample.** `receipt_sample` queries the last
   transaction of a bounded number of senders. It is not a full receipt scan;
   the authoritative inclusion count is the nonce delta.
8. **Histogram quantiles are bucket-interpolated.** `+Inf` is censored.
9. **No public-validator load.** The matrix refuses the public hosts; it cannot
   provide capacity evidence for them.
10. **Dirty working trees are labelled.** The report records the commit and the
    number of changed files. A dirty tree means the number belongs to that
    tree, not to the commit alone.

### Cells this environment does not produce

| cell family | why it is not measured here |
|---|---|
| `N=32`, `N=128` | no honest cluster of that size was provisioned on this host; a single-host mock would misrepresent consensus cost |
| `5,000 tx/s` with default `--senders 128` | almost certainly sender-bound; only meaningful with a larger funded sender set and a raised RPC limiter |
| public cluster | explicitly forbidden by the guard rails and AGENTS.md §6 |
| BFT finality latency | not exposed by the harness or `/metrics`; would need a finality observer |
| per-validator CPU across N nodes | the matrix uses one metrics URL; multi-node aggregation is a separate exercise |
| full reverted-transaction scan | receipts are sampled, not exhaustively indexed by this harness |

An operator with real 32/128-validator hardware can fill those rows by running
the same script against that cluster and reusing the results directory. Until
then the rows stay `NOT MEASURED` — and that is the honest output.

---

## 7. Files

| file | role |
|---|---|
| `scripts/perf-matrix.sh` | guard rails, cell loop, metrics snapshots, report renderer |
| `scripts/loadtest/metrics-delta.awk` | Prometheus histogram delta + bucket interpolation |
| `scripts/loadtest/loadtest/src/main.rs` | harness: per-tx confirmation sampling |
| `scripts/loadtest/loadtest/src/stats.rs` | harness: `confirmation_latency_s` distribution + JSON |
| `scripts/loadtest/README.md` | harness flags, safety model, report fields |
| `run/perf-matrix/<stamp>/` | raw cells + `summary.md` + `matrix.jsonl` (gitignored) |
