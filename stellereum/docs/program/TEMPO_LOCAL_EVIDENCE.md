# TEMPO_LOCAL_EVIDENCE — real-binary local-cluster tempo (defaults)

Date: 2026-11-02. Scope: measurement ONLY, no code/script changes.
Question: does the sim tuning recipe (base 650ms + straggler grace
1500/1500/3000 + 250ms slow link → ~483ms/block) hold on real binaries?

Short answer: **untestable here (no env passthrough), and defaults-only
numbers do NOT support a 0.6s/block claim** — p50 is ~0.25s but the mean is
seconds, with ~20s-quantum stalls and two ~41s chain-wide pauses in 103 blocks.

## 1. Setup

- Binary: `stellereum/target/debug/stellereum` (pre-existing, 55MB, 2026-11-02
  03:05 build). No builds performed; script never builds.
- Read first: `scripts/local-cluster.sh` (537 lines) + `scripts/local-cluster.md`.
- Command: `./scripts/local-cluster.sh up 3` → single-shard, fresh chain
  (`STELL_NEW_CHAIN=1`, keys regenerated).
- `up` result: epoch `b76feefadaf33c5a` identical on all 3 nodes, 5 common
  FINALIZED heights at boot, `status` all alive/finalizing, RPC head #5/#5/#5.
- Ports as documented: P2P 19411–19413, RPC 18646–18648, explorer 18081–18083.
  Live `multinode/nodeB` (pid 38707, port 9410) untouched throughout.
- Measurement basis: log snapshots `snap{1,2,3}.log` frozen at 07:30:30Z
  (~9 min of chain life, first FINALIZED 07:21:38Z). One FINALIZED line on
  node1 was unparseable (timestamp wrap) — excluded, negligible (1/89).

## 2. Why the recipe is untestable without script changes (defaults-only run)

`scripts/local-cluster.sh` has **no env passthrough** for tempo knobs:

- `write_configs` (line ~176) hardcodes into `run/cluster/node<i>/env.i`:
  `STELL_ROUND_TIMEOUT_MS=10000`, `STELL_BROADCAST_JOIN_MS=2000`,
  `STELL_CATCHUP_BUDGET_MS=8000`. Regenerated on every `up`.
- `boot_node` (line ~201) does `set -a; source env.i` in a subshell, so
  `env.i` **overwrites** anything exported in the caller shell.
- `STELL_STRAGGLER_*` appears **nowhere** in the script (verified by grep);
  code defaults (`main.rs`: `STRAGGLER_GRACE_MS_DEFAULT=0` = disabled,
  `CAP=30_000`) therefore apply.

So `export STELL_ROUND_TIMEOUT_MS=650 ...` before `up` is silently discarded.
Setting base 650 + grace 1500/1500/3000 requires editing the script or `env.i`
flow — both forbidden by task constraints. **Measured at defaults instead.**

## 3. Measurements (defaults: base 10000ms, join 2000ms, catchup 8000ms, grace OFF)

Method: per-node deltas between consecutive FINALIZED timestamps
(`[consensus] FINALIZED block #H …` ISO timestamps); view-change rate from
`[consensus] view change -> height H round R` lines; r0 share = finalized
heights with zero view-change lines; fork check = per-height hash compare
across nodes + divergence/fork grep (all zero).

### 3a. Per-height finalization latency (consecutive heights, per node)

| node | n  | mean (s) | p50 (s) | p99 (s) | min (s) | max (s) |
|------|----|----------|---------|---------|---------|---------|
| node1 | 81 | 1.759 | 0.254 | 21.530 | 0.190 | 21.761 |
| node2 | 90 | 3.136 | 0.255 | 24.120 | 0.189 | 24.382 |
| node3 | 86 | 4.109 | 0.258 | 41.063 | 0.190 | 41.910 |

First-15 deltas (node2, s):
`0.20 0.26 0.19 1.20 0.25 0.20 0.25 0.25 1.18 0.19 0.25 0.25 0.25 20.32 20.25`
— fast path ~0.2–0.3s interleaved with ~1.2s and ~20s steps.

### 3b. Network-level (first FINALIZED per height across cluster, n=102)

mean **5.140s**, p50 **0.281s**, p99 **40.727s**, max 41.9s.
Shape buckets: 63× <1s, 17× 1–2s, 9× other (2–19s), 11× ~20s, 2× ~40s.
Gaps >30s (chain-wide): **h35: 41.9s, h77: 40.9s** (2 events; chain recovered
both times, union heights 1..103 complete with no holes).

The ~20s quantum matches the defaults budget exactly:
10s round timeout + 8s catchup + 2s join = 20s per failed round
(40–42s = two failed rounds, 62s = three). Failure mode on real binaries is
20s-quantum stalls, not a 250ms slow link.

### 3c. View-change rate / r0-decision share

| node | FINALIZED | VC events | VC/block | heights w/ ≥1 VC | r0 share | deepest round |
|------|-----------|-----------|----------|------------------|----------|---------------|
| node1 | 88 | 20 | 0.136 | 10 | **88.6%** | r3 @ h78 |
| node2 | 97 | 21 | 0.186 | 16 | **83.5%** | r3 @ h36 |
| node3 | 94 | 20 | 0.213 | 17 | **81.9%** | r3 @ h78 |

(Caveat: nodes that sync-jump a height log no VC lines for it, mildly
inflating r0; node2 has fewest skips (97/103) and still shows 83.5%.)

### 3d. Fork check

- Union heights 1..103, zero missing everywhere, 81 heights common to all 3
  nodes (remainder = per-node sync-jumps, not forks).
- Per-height block-hash agreement: **0 mismatches**.
- `divergence|DIVERGENCE|fork` grep over all 3 snapshots: **0 lines**.
- No height stalled permanently; max network head #103 on all RPCs at snapshot.

## 4. Teardown

`./scripts/local-cluster.sh down` stopped pids 45271/45289/45309; `node.pid`
files gone; `status` = all `no`; `ss` shows no listeners on
19411–13/18646–48/18081–83 (two node3 sockets lingered seconds in close, then
freed); no stray cluster processes. Live nodeB untouched.

## 5. Verdict on the 0.6s claim for real binaries

**NOT proven — and defaults data leans against a naive transfer:**

1. The recipe was never applied to real binaries here (no passthrough, §2).
   The sim's ~483ms number has zero real-binary confirmation either way.
2. At 10s defaults the real cluster is bimodal: r0 fast path p50 ≈ 0.25–0.28s
   (sub-second IS the common case, 80/102 network heights <2s), but the mean
   is 5.1s network-level because ~13% of heights eat 20s-quantum stalls and
   2/102 ate ~41s chain-wide pauses.
3. For a 650ms base to average ~0.5s/block, it must nearly eliminate the
   20s-quantum failure steps that dominate the mean. Nothing in this run
   tests whether tighter timeouts do that or make view-change storms worse
   (tighter base + same failure fraction = worse, since backoff multiplies
   the base).
4. Honest projection from this data only: r0 heights already finalize in
   ~0.25s at defaults; the claim to prove is about the tail, and the tail
   here is quantized by the timeout/catchup/join budgets the recipe changes.

To actually prove the shape: add opt-in env passthrough for
`STELL_ROUND_TIMEOUT_MS` / `STELL_STRAGGLER_{GRACE,GRACE_CAP,FRESHNESS}_MS`
to `local-cluster.sh` (human-approved script change), re-run this exact
protocol at base 650 + grace 1500/1500/3000, and compare §3 tables —
aborting back to defaults on any >30s stall or hash mismatch.
