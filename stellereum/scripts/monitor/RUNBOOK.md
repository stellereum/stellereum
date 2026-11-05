# Stellereum node runbook (two-node stand, ~10 GB box)

Companion to `check.sh` (fast triage), `alerts.rules` (what pages) and
`prometheus.yml` (what is scraped). All commands assume you are on the box
(`ssh root@<node-A-host>`); gateway = `127.0.0.1:8080`, RPC = `8545` (A) /
`8546` (B), logs = `/root/nodeA/current.log`, `/root/nodeB/current.log`,
control script = `/root/stellereum/scripts/stell-node.sh`
(or `./scripts/stell-node.sh` from a repo checkout with `STELL_ROOT=/root`).

> **Binary-age caveat (live since 2026-09-26):** the deployed binary predates
> the readiness surface — `/healthz` and `/readyz` answer **404** and
> `/metrics` exports **no `stell_ready` gauge**. On such a binary:
> any HTTP response (even 404) still means "process alive"; use the
> *legacy* diagnose path (`/metrics` heights + two RPC samples + log greps).
> After the next `deploy`, `/readyz` names the exact failing condition and
> `stell_ready` mirrors it. `check.sh` handles both cases automatically.

Fast triage (read-only, changes nothing):

```bash
bash scripts/monitor/check.sh --explorer http://127.0.0.1:8080 --rpc 8545
bash scripts/monitor/check.sh --explorer http://127.0.0.1:8080 --rpc 8546
./scripts/stell-node.sh status            # heights, roots, finalizes, verdict
```

---

## StellNodeDown (critical) — process unreachable

**Means:** Prometheus got no `/metrics` scrape for 1m, or `check.sh` exits 2
(`DOWN: process unreachable`, curl refused/timed out). The process is dead —
or the box/network path is.

**Diagnose (exact):**

```bash
curl -s -m 5 -o /dev/null -w 'healthz HTTP:%{http_code}\n' http://127.0.0.1:8080/healthz
pgrep -af 'stellereum run'                        # expect 2 lines (nodeA + nodeB)
ss -ltn | grep -E '8545|8546|8080'                 # expect all three LISTEN
tail -50 /root/nodeA/current.log                  # panic? OOM? lock error?
tail -50 /root/nodeB/current.log
dmesg | tail -20                                  # OOM-killer?
df -h /                                           # 100% disk also kills writes
```

**Fix:** restart keeps the chain: `./scripts/stell-node.sh stop` then `start`
(or `restart`), then `./scripts/stell-node.sh wait` (blocks until both nodes
advance). If it fails with `could not acquire lock on ./data/store/db`,
a process is still alive — `pgrep`, `kill`, wait for the lock, never `rm` it.

**Escalate** if: processes die again within minutes (panic loop — save the log
tail), OOM-killer fired (box needs swap/cgroup limits, not restarts), or the
box itself is unreachable (provider console, not this runbook).

**Abort:** do not `wipe`/`clean` for a down process — wiping deletes the chain
to fix a process problem. Do not restart while disk is 100% (free space first,
see disk section).

---

## StellNotReady (critical) — alive but not ready

**Means:** process answers HTTP but `/readyz` returns 503 for 2m
(`stell_ready == 0`). The node is running yet useless. The response names the
cause — read it before doing anything:

```bash
curl -s -m 5 -w '\nHTTP:%{http_code}\n' http://127.0.0.1:8080/readyz
# {"ready":false,"failed_checks":[...],"height":N,"peers":P,...}
```

Route by `failed_checks`:

| reason | meaning | go to |
|---|---|---|
| `no_peers` | zero peer connections | peer-loss section below |
| `no_finality` + `height_zero` | nothing ever finalized, height 0 (DHT warmup / pre-consensus) | StellHeightZero |
| `finality_stalled` / `height_stalled` | no finalize / no height advance for >30 s | StellFinalityStalled |

**On a legacy binary (no `/readyz`):** emulate it:

```bash
curl -s -m 8 http://127.0.0.1:8080/metrics | grep -E '^(stell_consensus_height|stell_consensus_round|stell_validator_set_size|stell_fork_total|stellereum_block_height)'
for p in 8545 8546; do curl -s -m 5 -X POST http://127.0.0.1:$p -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'; echo; done
sleep 10
for p in 8545 8546; do curl -s -m 5 -X POST http://127.0.0.1:$p -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'; echo; done
grep -o 'FINALIZED block #[0-9]*' /root/nodeA/current.log | tail -3
grep -o 'FINALIZED block #[0-9]*' /root/nodeB/current.log | tail -3
```

---

## StellFinalityStalled (critical) — height not advancing

**Means:** `stell_consensus_height` unchanged for ~3m (Prometheus window ≈ 3×
the 30 s readiness N). Live failure modes seen: view-change spin with zero
finalizes, RPC answering at a fixed height forever, peer loss. (Observed live
2026-09-26 ~13:00 UTC: both RPCs pinned at `0xc2`/194, last `FINALIZED #194`
~4 h earlier, `stell_consensus_round 0`, votes `0/0`, `validator_set_size 0`.)

**Diagnose (exact):**

```bash
./scripts/stell-node.sh status
grep -c FINALIZED /root/nodeA/current.log /root/nodeB/current.log
grep 'FINALIZED' /root/nodeA/current.log | tail -3
grep 'FINALIZED' /root/nodeB/current.log | tail -3
# view-change / round spin with zero finalizes?
grep -ciE 'view change|round change|new round|timeout' /root/nodeA/current.log | tail -1
tail -100 /root/nodeA/current.log | grep -iE 'quorum|peer|dht|view|round|finaliz' | tail -15
# stale-chain marker (pre-quorum blocks, unverifiable by design)?
grep -l 'lacks a validator quorum' /root/nodeA/current.log /root/nodeB/current.log
# fork counter rising? (monotonic; any increase since last check is news)
curl -s -m 8 http://127.0.0.1:8080/metrics | grep -E '^stell_fork_total'
```

**Restart vs wipe vs escalate:**

- **Restart** (`restart`, keeps chain) when: both nodes agree on the last
  finalized root but nothing advances (wedged consensus, dead peer link that
  re-dials on boot). Then `wait` to confirm advancement.
- **Wipe** (`wipe`/`clean`, deletes both data dirs, new genesis) ONLY when:
  `status` prints `STALE CHAIN` (`lacks a validator quorum` in logs — old
  blocks are unverifiable by design, no restart can fix that), or both nodes
  are stalled AND agree AND a restart did not move them. Wipe takes both
  nodes (genesis root must match); never wipe one node alone.
- **Escalate** (do not keep restarting) when: state roots/heights DIVERGE
  between A and B, `stell_fork_total` is rising (chain split — needs consensus
  debugging, not ops), restart+wipe both fail to advance, or logs show
  repeated panics. Save `current.log` tails + `status` output for the report.

**Abort:** stop the restart loop after 2 failed restarts without new evidence;
abort `wipe` if the two nodes disagree (wiping destroys the only copy of each
side's divergence evidence — snapshot logs first); abort everything if disk
is ≥95% (free space first).

---

## StellHeightZero (warning) — height 0 forever

**Means:** height never left 0 for 10m; RPC answers but the node is stuck
pre-consensus (DHT warmup that never completes, no peers, genesis/config
mismatch). `/readyz` shows `height_zero` + `no_finality` (+ usually
`no_peers`).

**Diagnose:**

```bash
curl -s -m 5 -w '\nHTTP:%{http_code}\n' http://127.0.0.1:8080/readyz
grep -ciE 'dht|bootstrap|peer|warmup' /root/nodeA/current.log
tail -60 /root/nodeA/current.log | grep -iE 'dht|peer|quorum|genesis|config|error' | tail -10
ls -la /root/nodeA/node.yaml /root/env.A        # config present?
```

**Fix:** usually environmental, not data: check the peer/bootstrap config,
`restart`, watch for the first `FINALIZED`. **Do not wipe** — there is no
chain to be stale yet; wiping a height-0 node changes nothing.

**Escalate** if peers never connect after restart (network/firewall/DHT
bootstrap issue) or logs show genesis/config errors.

---

## StellNoPeersSuspected (warning) — peer loss

**Means (best-effort):** no per-peer `stell_peer_latency_seconds_*` series for
15m. There is **no peer-count metric and no peer RPC**, so this alert cannot
prove peerlessness — it only says "no peer was measured". The proof is
`/readyz` `failed_checks` containing `no_peers` (post-readiness binary) or
the logs.

**Diagnose (exact):**

```bash
curl -s -m 5 http://127.0.0.1:8080/readyz            # failed_checks has no_peers?
grep -ciE 'peer|dht' /root/nodeA/current.log
tail -100 /root/nodeA/current.log | grep -iE 'peer|dht|connect|dial|bootstrap' | tail -10
tail -100 /root/nodeB/current.log | grep -iE 'peer|dht|connect|dial|bootstrap' | tail -10
ss -tun | head -20                                   # any outbound peer sockets?
```

**Fix:** single-node link drop → `restart` the affected node (re-dials).
Stand-wide peer loss right after a cold start can be DHT warmup — wait through
one `wait` cycle before touching anything.

**Escalate** if both nodes permanently see zero peers (bootstrap/network, not
a node problem). **Abort** remediation if height is still advancing — a
soloing node that finalizes is degraded, not broken; do not wipe a live chain
to fix a warning.

---

## StellDiskFullWarning / StellDiskFullCritical + StellDiskFillingFast

**Means:** `/` above 85% (warning) / 95% (critical), or `predict_linear`
says current growth fills the disk within ~6h. The box is 9.8 GB and idles at
~92–93%, so these fire on normal operation, not just incidents. Growth
drivers, in order: **systemd journal (~1 GB)**, stale `*.log` files in
`/root/nodeA|B` (dozens, incl. a ~58 MB `live.log`; `current.log` grows
~7 MB/hour/node), build tree `/root/stellereum` (~1.6 GB, mostly `target/`),
chain data (`/root/nodeA|B/data`, only ~3 MB each — NOT the problem).

**Diagnose (exact, read-only):**

```bash
df -h /
du -x -s /* 2>/dev/null | sort -rn | head -8
du -sh /root/nodeA /root/nodeB /root/stellereum
ls -laS /root/nodeA/*.log | head; ls -laS /root/nodeB/*.log | head
du -sh /root/nodeA/data /root/nodeB/data
journalctl --disk-usage
```

**Fix (in this order; stop when comfortably below 85%):**

1. `journalctl --vacuum-size=200M` — journal is the biggest safe win (~1 GB).
   (Persistent cap belongs in `/etc/systemd/journald.conf`: `SystemMaxUse=200M`.)
2. Delete **stale** `*.log` in `/root/nodeA|B` (old `run*.log`, `v3.log`,
   `live.log`, `ops-*`, single letters) — never the active `current.log`
   while the node runs (it holds the only `FINALIZED` history `status` reads).
3. Confirm rotation is on: `STELL_LOG_MAX_BYTES` (default 10 MiB) /
   `STELL_LOG_MAX_FILES` (default 5) bound `current.log` to ~50 MB total;
   without them growth is unbounded (see `SizeRotatingWriter` in
   `src/metrics.rs`).
4. Only if desperate: `cargo clean`-style purge of `/root/stellereum/target`
   (costs the next rebuild; coordinate — another agent may be building).

**Never:** delete `/root/nodeA|B/data` to free space (that is a `wipe` with
extra steps and forks the two nodes); restart into a full disk (writes fail,
locks wedge); vacuum the journal before saving evidence during an active
consensus incident.

**Escalate** if usage rebounds within hours after cleanup (runaway log level
or a growth driver not listed here — report `du` output), or disk errors
appear in `dmesg` (hardware, not housekeeping).

**Abort criteria (all sections):** abort restarts while disk ≥95%; abort
`wipe`/`clean` on divergent nodes before logs are snapshotted; abort the
restart loop after 2 consecutive failures with no new evidence and escalate
with `status` output + the last 100 log lines of each node.
