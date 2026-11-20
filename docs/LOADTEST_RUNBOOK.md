# LOADTEST_RUNBOOK — Wave-2 procedure

Status: operator runbook for the standalone harness in
`scripts/loadtest/`. It describes a **planned** three-wave measurement plus the
**measured 2026-11-20 baseline** in §0. Nothing else here is a result; record
only pasted command output.

Read `scripts/loadtest/README.md` first. The short version:

* the harness is **dry-run by default**;
* sending requires `--allow-live`; the live cluster additionally requires
  `--operator-order`;
* it never funds accounts, never calls the faucet/staking/governance methods,
  and never restarts a node.

AGENTS.md §6 applies to every step: the live cluster is read-mostly, and a
transaction wave is allowed only on an explicit human order that names the
rate, window, endpoints and stop conditions.

---

## 0. Measured baseline — 2026-11-20

These are **measurements**, not targets or promises. One run per rate, 50
deterministic senders, against the live cluster; the harness reported zero
429s in all three runs.

| Target tx/s | Achieved accepted tx/s | 429s | Block time p50 | Block time p99 |
|---:|---:|---:|---:|---:|
| 60 | 57.6 | 0 | 0.202 s | 0.802 s |
| 200 | 90.1 | 0 | 0.401 s | 1.552 s |
| 500 | 107.4 | 0 | 0.401 s | 1.406 s |

`Achieved accepted tx/s`, p50 and p99 are copied from the harness report for
the sending window. The block-time percentiles are the harness's observed
`stell_blockNumber` arrival intervals, not node-stamped block intervals.

### Commands

One invocation per rate; only `--rate` and the output paths changed:

```bash
cd /home/imm/stellereum-project
BIN=scripts/loadtest/loadtest/target/release/stell-loadtest
COMMON=(--allow-live --allow-remote --operator-order \
        --url https://rpc.stellereum.org \
        --watch-url https://rpc.stellereum.org \
        --senders 50 --duration 60)

"$BIN" "${COMMON[@]}" --rate 60 \
  --json-out /tmp/opencode/baseline-60.json | tee baseline-60.log
"$BIN" "${COMMON[@]}" --rate 200 \
  --json-out /tmp/opencode/baseline-200.json | tee baseline-200.log
"$BIN" "${COMMON[@]}" --rate 500 \
  --json-out /tmp/opencode/baseline-500.json | tee baseline-500.log
```

The wave log header (`endpoints:`, `watch:`, `target:`) is the authority on
the exact endpoints and window; keep the three logs and JSON files with the
numbers above.

### What these numbers mean — and do not mean

1. **The ceiling was sender-bound, not node-bound.** 50 senders sustain about
   `2.1 tx/s × 50 ≈ 105 tx/s`; the 200 and 500 runs produced 90.1 and 107.4
   accepted tx/s (≈1.8–2.1 tx/s per sender), so the sender set was the binding
   constraint, not demonstrated node capacity. **107.4 tx/s is not a 500 tx/s
   result.**
2. **Zero 429s does not prove headroom.** At 50 senders the offered load never
   reached the per-IP RPC limiter, so the limiter was not exercised. Do not
   cite this baseline as evidence that a 500 tx/s wave will be accepted.
3. **Validators A and D are 1-vCPU hosts.** Their CPU is part of what the
   block-time p50/p99 shows; this is a resource-constrained testnet baseline,
   not a capacity benchmark for larger hardware.
4. **The correct RPC limiter env names are `STELL_STANDALONE_RATE_LIMIT`
   (default 300/s per IP; legacy alias `STELL_RPC_RATE_LIMIT_PER_SEC`) and
   `STELL_RATE_LIMIT_PER_SEC` for the gateway/explorer on :8080 (default
   30/s).** `STELL_RATE_LIMIT_PER_SEC` alone does not raise the JSON-RPC
   limiter.
5. These were three single 60 s runs, not a soak and not an acceptance gate.
   Mempool peak, included tx/s, CPU and per-node heights from those runs were
   not preserved here; treat those fields as **UNVERIFIED** for the baseline.
   Re-run with §5's recording checklist before making a capacity claim.

To measure the node rather than the sender set, raise `--senders` (see §3.3)
and keep the per-sender in-flight limit at 4.

---

## 1. Preconditions (all must be true)

1. **Human order.** The order names: target node(s), the three rates
   (60/200/500 tx/s), the 15-minute window, the person watching the cluster,
   and the rollback (stop the harness; no node restart).
2. **Build is green.**
   ```bash
   cd /home/imm/stellereum-project
   cargo build --release --offline \
     --manifest-path scripts/loadtest/loadtest/Cargo.toml
   ```
3. **Dry run is green.** Paste its output into the wave log:
   ```bash
   BIN=scripts/loadtest/loadtest/target/release/stell-loadtest
   "$BIN" --dry-run --senders 256 | tee wave0-dryrun.log
   ```
   The last line must be `DRY RUN OK ...` and the exit code must be `0`.
4. **Local rehearsal is green.** Run one short wave against the local test
   node (node B at `127.0.0.1:8546`, or a disposable dev node), never the live
   cluster:
   ```bash
   "$BIN" --allow-live --url http://127.0.0.1:8546 \
     --senders 32 --rate 10 --duration 60 \
     --json-out /tmp/opencode/rehearsal.json
   ```
   Rehearse until the report is `PASS` with `backlog after drain: 0`.
5. **Sender funding is confirmed.** Print the complete roster, one address per
   line, and capture the machine-readable total:
   ```bash
   "$BIN" --allow-live --print-all-senders \
     --url http://127.0.0.1:8546 --senders 256 \
     | tee /tmp/opencode/senders-256.txt
   ```
   Verify `grep -c '^0x' /tmp/opencode/senders-256.txt` equals the
   `SENDERS_TOTAL=` line. Fund those addresses from a testnet
   faucet/treasury **before** the wave. `--print-all-senders` is read-only,
   sends no transaction, and prints the full set even when every sender is
   unfunded (exit 0). A live wave still refuses to start when any sender is
   below one transaction's cost. `--preflight-only` remains the balance gate
   (exit 3) and its refusal block only shows the first 50 unfunded senders —
   use `--print-all-senders` when the set is larger than that.
6. **Rate limit is known.** The node's standalone JSON-RPC budget is
   `STELL_STANDALONE_RATE_LIMIT` (default **300/s per IP**; the legacy alias
   `STELL_RPC_RATE_LIMIT_PER_SEC` is honoured when the new name is unset).
   The gateway/explorer on `:8080` has a separate, much smaller
   `STELL_RATE_LIMIT_PER_SEC` (default 30/s) — changing that does **not**
   raise the JSON-RPC limit. A 500 tx/s wave from one IP needs the target
   node's standalone limiter configured at least `target + reads` (recommend
   `2000`). Changing it on the live cluster requires a restart and therefore
   a separate human order. If it is not raised, the 500 wave will report 429s
   and is **not** a valid throughput measurement.
7. **Baseline snapshot** (read-only):
   - heights A/B/C/D,
   - mempool size,
   - current base fee (`stell_baseFee`),
   - 60 s of node CPU on each 1-vCPU host,
   - current block interval (last 100 blocks).

---

## 2. What the harness does per wave

* Deterministic Falcon-512 senders, one OS thread each.
* Target rate enforced by a global token bucket; concurrent requests bounded
  by `--max-inflight`.
* At most **4** accepted-but-unexecuted nonces per sender (the node's
  `NONCE_FUTURE_WINDOW`; a larger number is rejected as a nonce gap).
* `--pq-mode auto`: nonce 0 per sender is an explicit activation transaction
  (public key + 45,000 gas surcharge); after it is included, later nonces omit
  the key. If a node lost its in-memory registry, the same nonce is re-signed
  explicitly.
* Transport retries resend the **same cached bytes** for the same nonce, so a
  retry cannot double-spend a nonce. A duplicate is counted as accepted.
* After the sending window: drain until accepted nonces are on-chain (or
  `--drain-timeout`), sample receipts, and report.

---

## 3. Wave commands

Use **one submit URL** per wave unless the order explicitly allows spreading
the sender set across nodes. Senders are load-balanced over repeated `--url`
values and stay pinned to one node, which keeps each nonce sequence local.

### 3.1 Local / node B

```bash
BIN=scripts/loadtest/loadtest/target/release/stell-loadtest
COMMON=(--allow-live --url http://127.0.0.1:8546 --senders 256 \
        --duration 900 --stall-seconds 30 --max-lag-blocks 500)

# Wave 1: 60 tx/s
"$BIN" "${COMMON[@]}" --rate 60 \
  --json-out /tmp/opencode/wave-60.json | tee wave-60.log

# settle 2 min, verify backlog 0, then Wave 2: 200 tx/s
"$BIN" "${COMMON[@]}" --rate 200 \
  --json-out /tmp/opencode/wave-200.json | tee wave-200.log

# only after Wave 2 PASS and the rate limit is raised: Wave 3: 500 tx/s
"$BIN" "${COMMON[@]}" --rate 500 \
  --backlog-stop-size 20000 --backlog-stop-secs 60 \
  --json-out /tmp/opencode/wave-500.json | tee wave-500.log
```

### 3.2 Live cluster (only with the order)

The public RPC is one endpoint. To compare validators, forward C/D locally
over SSH and pass loopback `--watch-url` values; never expose a new public
port. `--watch-url` is read-only.

```bash
BIN=scripts/loadtest/loadtest/target/release/stell-loadtest
"$BIN" --allow-live --allow-remote --operator-order \
  --url https://rpc.stellereum.org \
  --watch-url https://rpc.stellereum.org \
  --watch-url http://127.0.0.1:8546 \
  --watch-url http://127.0.0.1:8547 \
  --watch-url http://127.0.0.1:8548 \
  --senders 256 --rate 60 --duration 900 \
  --stall-seconds 30 --max-lag-blocks 500 \
  --json-out /tmp/opencode/wave-live-60.json | tee wave-live-60.log
```

The same command with `--rate 200` and then `--rate 500` after the previous
wave passes. If `--operator-order` is absent, the harness refuses before the
first packet; if `--allow-remote` is absent, it refuses any non-loopback URL.

### 3.3 Sender-count guidance

A sender is sequential: sustained per-sender rate ≈ `1 / RTT`. The node's
per-IP budget is usually the binding limit, not the sender count.

| Target | Suggested `--senders` | Per-sender rate at 900 s |
|---|---|---|
| 60 tx/s | 64 | ~0.94 tx/s |
| 200 tx/s | 128 | ~1.6 tx/s |
| 500 tx/s | 256 | ~2.0 tx/s |

Measured caveat (2026-11-20): at 50 senders the achieved rate topped out at
107.4 accepted tx/s (~2.1 tx/s per sender), so the 200/500 rows above are a
sender-count plan, not evidence of node capacity. Increase senders until the
per-sender rate stops being the limiter, then measure again.

Do not raise `--inflight-per-sender` above 4; the node rejects the resulting
gap.

---

## 4. Funding math (testnet tokens)

The node charges an empty-payload transfer its declared `gas_limit`. With the
live base fee of 280,000 gas and `--gas-margin 1000`:

* explicit activation tx: `280,000 + 45,000 + 1,000 = 326,000` gas as the
  declared `gas_limit`; execution additionally debits the 45,000 activation
  surcharge, so the activation transaction's total cost is `326,000 + 45,000`
  gas plus `amount`;
* steady-state implicit tx: `280,000 + 1,000 = 281,000` gas (no surcharge);
* `--recipient self` (default) returns `amount` to the sender, so the net cost
  is the fee, not the amount.

| Wave | txs at 15 min | approximate gas (nano-STELL) | ≈ STELL |
|---|---:|---:|---:|
| 60 tx/s | 54,000 | 15.2 × 10^9 | 15.2 |
| 200 tx/s | 180,000 | 50.6 × 10^9 | 50.6 |
| 500 tx/s | 450,000 | 126.5 × 10^9 | 126.5 |
| total + 10% buffer | — | — | **≈ 212** |

The table uses the steady-state 281,000 gas limit. The one-time activation
costs an extra 90,000 gas per sender (45,000 higher declared limit + 45,000
execution surcharge), i.e. 23 million gas for 256 senders, which is inside the
buffer. For 256 senders, budget **≈ 1 STELL per sender** for the three waves.
The mempool reserves `amount + gas_limit` per pooled transaction, so each
sender needs at least one transaction's cost available at all times; the
harness preflight enforces that minimum. Recompute if `stell_baseFee` changes.

---

## 5. What to record per wave

Copy these from the report text and JSON; do not retype numbers.

| Field | Source |
|---|---|
| wave rate / window / senders / endpoints | command line + report header |
| submitted / accepted / failed / duplicates / 429s | report counts |
| achieved accepted tx/s | report rates |
| included count + included tx/s + backlog after drain | report |
| block time p50/p95/p99 (observed) | report `block_time_s` |
| tx per block p50/p95/max, zero-tx blocks | report `tx_per_block` |
| node-reported interval / metrics interval | report |
| mempool start / peak / end | report |
| height start → end (+delta) | report |
| per-wave verdict + exit code | report |
| watch height spread | report / `--watch-url` |

Also record, outside the harness:

* **Node CPU** on each 1-vCPU host for the whole window:
  `pidstat -p "$(pgrep -f 'stellereum' | head -1)" 1 900`
  (or `top -b -d 1 -n 900 -p <pid>`), plus load average and free memory.
* **Node C height** relative to A/B/D every minute (the harness aborts at
  `--max-lag-blocks 500`, but record the curve).
* **Any restart, view change, log error or RPC 5xx** seen by the operator.
* **Clock**: UTC start/end, and the `--json-out` path.

Wave evidence bundle: `wave-N.log`, `wave-N.json`, the node CPU capture, and a
one-screen note with the commands. Mark anything not pasted as **UNVERIFIED**.

---

## 6. Between waves

1. Confirm `backlog after drain: 0` in the report. If not, **stop**.
2. Watch `stell_mempoolSize` until it returns to the baseline and stays there
   for 2 minutes.
3. Confirm all four heights advance for 2 minutes.
4. Re-check `stell_baseFee`; funding and gas limits depend on it.
5. Take the CPU/memory snapshot.
6. Only then start the next, higher wave.

Do not run two waves concurrently. Do not leave a wave running unattended.

---

## 7. Stop conditions (mandatory)

Stop the harness and do not raise the rate if any of these is true. The first
three are also enforced by the tool when the corresponding flags are set.

1. **Chain stall > 30 s.** No new finalized height on the watched node for 30
   seconds. Harness: `--stall-seconds 30` → `ABORTED`.
2. **Mempool backlog growth without drain.** Mempool stays above the
   operator-chosen level for the whole window (for example 20,000 for 60 s),
   or the post-wave backlog is non-zero. Harness:
   `--backlog-stop-size 20000 --backlog-stop-secs 60`.
3. **Node C falls behind by > 500 blocks** (or any watched validator does).
   Harness: `--max-lag-blocks 500` with multiple `--watch-url` values →
   `ABORTED`.
4. **Rate-limit storm.** More than 1% of submissions end as 429/rate-limit, or
   the node returns 5xx. The measured rate is invalid; fix the budget or lower
   the target.
5. **Rejection share > 1%.** Any `failed > 0` is printed with its class and
   first message. Insufficient balance, fee-too-low, bad signature or nonce
   errors mean the wave is invalid.
6. **CPU saturation.** A 1-vCPU validator above ~90% for more than 60 s, or
   load average far above 1.0.
7. **Block-time tail.** p99 block time > 5× p50, or a sustained rise across
   the window. Do not "push through" to 500.
8. **Any divergence/restart/fork signal** in node logs. Stop and escalate; do
   not restart a live validator without the operator.

After a stop: keep the JSON/logs, record the height on every node, and do not
delete store data, the running binary or the only snapshot (AGENTS.md §6).

---

## 8. End of Wave 2

1. Stop after Wave 3 (or after the last wave that passed).
2. Archive `wave-*.log` and `wave-*.json` with the CPU captures.
3. Summarise per wave: target vs achieved accepted tx/s, included tx/s,
   block-time p50/p99, backlog, 429s, CPU. Use the JSON fields, not memory.
4. State clearly whether the 500 tx/s wave was valid (rate limit raised,
   backlog zero, no stop condition). A failed or aborted wave is a valid
   result; do not re-label it.
5. Do not leave the harness, tunnels or background watchers running.

---

## 9. Known limits

* Empty-payload native transfers only; the encoder refuses non-empty SVM
  payloads rather than emit a possibly misread wire form.
* Block-time percentiles use `--poll-ms` (default 200 ms) wall-clock arrival
  and the node's second-granularity timestamps only as a cross-check.
* The receipt sample is bounded; the exact included count is the on-chain
  nonce delta.
* View-change counts are intentionally **not** measured by this harness.
