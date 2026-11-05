# TEMPO_PROFILE — local-cluster + virtual-clock measurements (2026-10-31)

Measurement + analysis ONLY. No live nodes touched. `scripts/local-cluster.sh`
used read-only (`up 3`, `status`, `down`). No src/tests/scripts changes.

## 1. Setup

- Binary: `stellereum/target/debug/stellereum` (resolves first per script).
- Cluster: 3 validators, single machine, loopback only.
  Ports: P2P `19411..19413`, RPC `18646..18648`, explorer `18080+i`.
- Consensus env (from `run/cluster/node<i>/env.<i>`, identical shape):
  `STELL_ROUND_TIMEOUT_MS=10000`, `STELL_BROADCAST_JOIN_MS=2000`,
  `STELL_CATCHUP_BUDGET_MS=8000`, single-shard (no `STELL_SHARDS`),
  quorum = unanimous 3/3 (powers `[1,1,1]`-equivalent; epoch identical on all
  nodes: `b76feefadaf33c5a`).
- Quorum math note: with N=3, `(2n/3)+1 = 3` — unanimity is FORCED, any single
  desynced member vetoes every QC (same coupling pinned by
  `stellereum/tests/unanimity3_slow_voter_tests.rs`: 3.5s base stalls,
  10s base finalizes).
- Slow-link injection: **NOT available**. `tc qdisc add dev lo root netem
  delay 250ms` → `RTNETLINK answers: Operation not permitted` (no
  CAP_NET_ADMIN in this environment); `tc qdisc show dev lo` still `noqueue`,
  nothing applied. Per task brief, virtual-clock sims used instead
  (`block_tempo_lan.rs` LAN + WAN contrast, `zz_vel_measure.rs`
  BEFORE/AFTER, release mode).
- Measurement window: from first `FINALIZED` on all nodes to analysis freeze.
  Heads at freeze: node1 `#183` (175 finals), node2 `#183` (175 finals),
  node3 `#182` (171 finals) — node3 repeatedly skips heights via sync
  catch-up (fewer FINALIZED lines, same hashes/roots → no fork).
  Common (finalized on all 3) heights: **1 → 182, n=162, span 565.0s**
  (first-finalized timestamps).

## 2. Raw numbers — local 3-node unanimity cluster (loopback, zero delay)

### 2.1 Per-height finalization latency (first-FINALIZED across nodes)

| slice | n (dts) | mean | p50 | p90 | p99 | max | min |
|---|---|---|---|---|---|---|---|
| all (early snapshot, 98 dts) | 98 | 2.210s | 0.252s | 1.157s | 40.624s | 42.016s | 0.194s |
| fast bucket (`<1s`) | 72 | 0.251s | — | — | — | — | — |
| slow bucket (`>=1s`) | 26 | 7.636s | — | — | — | — | — |

Full-window time attribution (162 common heights, 161 dts, span 565.0s):

| bucket | n | sum | share of span |
|---|---|---|---|
| fast `<1s` (happy path) | 113 | 28.0s | **5.0%** |
| mid `1–5s` (~1s vote-late events) | 31 | 38.7s | **6.9%** |
| stall `>=5s` (multi-round veto) | 17 | 498.3s | **88.2%** |

Stall transitions (height→height dt): `50→52` 20.5s, `65→67` 40.6s,
`72→74` 21.7s, `77→79` 42.0s, `82→84` 21.7s, `102→104` 28.8s,
`105→108` 30.7s (+ further stalls to head, 17 total).

### 2.2 Rounds / view changes (from `propose-gate h=X r=Y` lines, node1)

Gated heights 1..~110: `r>0` seen at h=1 (genesis transient, r0+r1),
**52 (r0+r1), 67 (r0+r1+r2), 74 (r0+r1), 79 (r0..r3), 84 (r0+r1+r2),
104 (r0+r1+r2), 107 (r0+r1)** → r0-decision rate **101/108 = 93.5%**
(excl. genesis). All other heights decide r0.

Per-rung dwell (gate-to-gate, measured): 19.18, 19.18, 20.03, 20.35, 20.25,
20.29, 20.27, 20.75s → **mean ≈ 20.0s ≈ 2× the configured 10s base**.
Once the round changes to an acceptable proposer, decide follows in
**0.14–0.50s** (e.g. #52 r1: gate→DECIDED 0.14s; #67 r2: 0.19s).

Nil-voters at stall heights (node1 `RX Prevote … target nil`):
node3 at 52r0, 67r0, 74r0, 79r3, 84r0; node2 at 79r0, 84r0, 110r0.
(Node ids: node1=`1d61a1fcfdcf`, node2=`b0939b21b597`, node3=`81013ffbd8b6`.)
Node3 is the chronic desyncer but node2 vetoes too — under unanimity ANY
single split member stalls the height.

### 2.3 Intra-height phases, fast path (node1, heights 6–100 sample)

- proposal→quorum-prevotes: **10–160ms** (2nd non-nil RX prevote)
- quorum-prevotes→DECIDED: **13–130ms**
- DECIDED→FINALIZED (apply/execution queue): **mean 66ms, p50 62ms,
  max 437ms (n=99)**
- Happy-path proposal→finalize total: **≈0.13–0.26s** (e.g. #46: RX proposal
  28.608 → prevotes +62ms → DECIDED +13ms → FINALIZED +61ms).

### 2.4 The ~1s vote-late events (mid bucket)

Either the prevotes or the precommits arrive **~965–1070ms late** while the
proposal itself is instant (often same-tick fast-forward prebuild, e.g. #47:
proposed +6ms after previous FINALIZED, votes +1019ms). Then decide+apply run
normal (~130ms). Total ≈ 1.1–1.2s, always r0. Examples (prop→votes ms):
#19: 966, #24: 1022, #33: 1071, #38: 968, #47: 1019, #62: 965, #69: 980,
#78: 967, #83: 969; votes→decided shape: #14: 981, #28: 980, #42: 983,
#57: 974, #85: 882, #88: 976.
Correlation (measured, causality ESTIMATE): every such height has a matching
`[sync] fetch_block_qc … height=N … failed (fetch miss/timeout)` line
(heights 5,10,14,19,24,28,33,38,42,47,52,53,57,62,67 — exact 1:1 with the
slow-height list). The ~1s looks like one backoff/timeout rung in vote
gossip or sync-prefetch racing consensus; NOT proposer waiting (proposal is
instant) and NOT rounds timing out (all r0, no view change).

### 2.5 Stall anatomy (measured, #52 and #67 on node1/node3)

\#52: node3 logged `caught up to height 51 while running (was 51); resumed
consensus at 52` — sync jumped it over #51 (it never logged FINALIZED #51,
nodes 1+2 did at :30.86). As #52-r0 proposer node3 broadcast `7c70bd26` but
**prevoted nil on its own proposal** (lock-split: locked on #51 while others
finalized it). Rebroadcasts at ~31.8/33.8/38.9/48.9s; `view change → r1` at
50.899 (**r0 dwell 19.13s**); r1 proposer node1 → all-value prevotes within
~120ms → DECIDED 51.088 → FINALIZED 51.148. Node3 finalized #52 (same hash
`b65266d3fdd0` on all nodes — no fork, it adopted #51 via sync).

\#67: same shape, two rungs — r0 19.18s (node3 nil), r1 20.03s (node3 never
voted r1, still emitting r0 nils), r2 proposer node1 → DECIDED in 0.19s,
FINALIZED +0.06s. Total height cost ≈ 39.5s.

Where the stall time goes (measured): **rounds timing out ≈ 100% of stall
dwell** — votes arrive in ~100ms throughout (both value and nil), nothing
waits on the proposer; the unanimity QC simply cannot form while one member
nil-votes from a stale lock, until proposer rotation + higher-round
justification unlocks it.

## 3. Raw numbers — virtual-clock sims (release, deterministic)

| sim | profile | mean | p50 | p99 | max | extra rounds | views/block |
|---|---|---|---|---|---|---|---|
| `lan_profile_100_blocks_tempo` | 4-node, delays 5/10/15/25ms, tick 50, timeout 800, 100 h | 300.0ms | 300ms | 300ms | 300ms | 0 | 0.0000 |
| `wan_contrast…` | 4-node, delays 80/120/180/250ms, tick 50, timeout 3500, 20 h | 640ms | 650ms | 700ms | 700ms | 0 | 0 |
| `vel_…_300` AFTER (prebuild+pipeline ON) | 4-node 2/3-quorum, WAN delays + propose delays 0,0,700,900ms, 300 h | 635.5ms | 650ms | 700ms | 700ms | 0 | 0.0000 |
| `vel_…_300` BEFORE (`VEL_BEFORE=1`) | same as above, fixes off | 1744.8ms | 750ms | 9300ms | 12800ms | 760 | 0.6333 |

VEL waste composition BEFORE (total extra over 700ms baseline: 310100ms):
proposer-late first-miss 138/300 heights (46.0%), 89700ms (**28.9%**);
votes-late cascade (rounds≥2) 36 heights, 193850ms (**62.5%**);
nil-prevotes 0; lock-splits 0; proposals refused 245 (vs ~2 AFTER).
AFTER: slow heights 0/300, first-miss 0ms, cascade 0ms, refused ~2.
r0 proposer slot counts [87,75,80,58] — slow members (idx2,3) propose ~46%
of slots yet cost nothing AFTER (fast-forward absorbs 700/900ms builds).

Pipeline isolation (60 h, prebuild ON both sides): mean ON 634.2ms vs OFF
684.2ms (**≈50ms/height, ≈7%**); extra rounds 0 vs 0. Deterministic
(fingerprint-identical reruns); no double-votes; no forks.

CPU probe (host, real crypto): `batch_verify_20tx = 0.462ms`,
`order_commit_20tx = 0.011ms` — sub-millisecond per block.

## 4. Verdict on the TEMPO-agent thesis ("<1% remains in code")

**CONFIRMED, with one refinement.** Numbers for:

- Floor: happy-path code+protocol costs **0.25s/height on loopback**
  (§2.3) and **0.64s/height under WAN delays + 700/900ms slow proposers**
  (VEL AFTER). Against live 60–300s/block (context-given testnet tempo):
  **0.64/60 ≈ 1.1% down to 0.64/300 ≈ 0.2%**. The code is ≤~1% of live tempo.
- Multiplier: on loopback with ZERO network delay, veto stalls still take
  **88.2% of wall-span** (§2.1). WAN physics (250ms home link) + slow
  proposer slots don't add code time — they raise desync probability, and
  each desync costs **~20s per rung** under unanimity. Live minutes =
  veto-rung count × ~20s, not slow code.
- The single biggest code lever **already landed**: prebuild fast-forward +
  vote pipeline cut in-sim mean **1745→636ms (−63%)** and 760→0 extra rounds
  in the 2/3-quorum profile. Remaining measured code items (apply ~60ms,
  pipeline ~50ms, CPU <1ms) are each <0.1% of live tempo — nothing left in
  code at the current margin except §5.3/§5.4 cleanups.

Numbers against (corrections to a naive "<1%, stop looking at code"):

- "Code" historically held the largest single measured gain (−63% in-sim);
  "<1%" is true of the CURRENT code, post-fix, not of code in general.
- Effective round dwell is **≈2× the configured timeout** (20.0s vs 10s
  base, 8 rungs). That factor-2 is a code-side timer-accounting issue
  (mechanism ESTIMATE: timer reset on vote/proposal activity — each stall
  shows continuous vote traffic during the dwell), and it doubles every
  live stall. Worth one investigation, not a rework.
- The loopback desync trigger (sync jump over an undecided height +
  apply-backpressure `deferring/rejected … apply still in flight`) is a
  different trigger than WAN stale-votes, but the veto MULTIPLIER it exposes
  is the same mechanism the `unanimity3` tests pin for the 250ms link.

## 5. Ranked levers (expected gain, evidence)

1. **Topology/quorum — add a 4th validator (or move the slow link).**
   Escapes forced 3/3 unanimity → 3/4 tolerates one desynced/slow member.
   Expected: removes the veto-stall class = **~88% of loopback span** and the
   minute-scale live stalls. Evidence: 4-node 2/3 sim = 0 view changes in 300
   heights WITH 700/900ms slow proposers; 3-node unanimity loopback = 17
   stalls/162 heights with NO delay. (No code change; needs 1 host + keygen.)
2. **Proposer logic — DONE (verify deployed): prebuild fast-forward + vote
   pipeline.** Measured −63% mean, −100% view changes in-sim. No further gain
   measurable in the 2/3 profile (slow slots fully absorbed). Only remaining
   proposer-side item is operational: avoid scheduling (or speed up) the
   250ms-link member's slots — topology again.
3. **Code (small): round-timer accounting.** Effective rung 20s vs 10s
   configured. If the timer is activity-reset, making it absolute halves every
   stall (20s→10s/rung). Expected: up to −50% of stall dwell, stalls remain.
   Investigation-sized, not a rework. (Mechanism ESTIMATE.)
4. **Code (small): ~1s vote-late events (~7% of span).** 1:1 correlation with
   `fetch_block_qc` miss lines; fix or decouple the ~1s wait (whichever side
   blocks). Expected: −7% local span; live impact ESTIMATE small (buried under
   veto rungs).
5. **Not levers (measured negligible): apply path (~60ms), batch verify
   (0.5ms), order commit (0.01ms), proposal fan-in (~100ms loopback).**
   Each <0.1% of live tempo. Do not touch for tempo reasons.

## Appendix — pasted evidence pointers (run/cluster/node<i>/live.log)

- Fast path: node1 `#46`: RX proposal 20:40:28.608 → prevotes .618/.671 →
  precommits .672/.674 → DECIDED .684 → FINALIZED .745.
- Vote-late: node1 `#47`: ff-proposed 20:40:28.751 → peer votes 20:40:29.768
  (+1017ms) → DECIDED .840 → FINALIZED .902.
- Stall #52: node3 `caught up to height 51 … resumed at 52` 20:40:31.157;
  node1 `view change -> height 52 round 1` 20:40:50.899;
  `proposed #52 r1` 20:40:50.956 → DECIDED 20:40:51.088 → FINALIZED 20:40:51.148.
- Stall #67: gates r0 20:40:58.214 → r1 20:41:17.395 → r2 20:41:37.429 →
  DECIDED 20:41:37.622; node3 FINALIZED #67 same hash `205d42498096`.
- Refused/deferred (benign, counted): `refused peer commit … height
  mismatch`, `deferring peer commit … apply still in flight`, `rejected
  proposal … apply in flight`, periodic `[sync] fetch_block_qc … failed`.
- No forks: all FINALIZED lines for a height share one hash+state-root across
  nodes (spot-checked #46, #51, #52, #67); `double_votes` equivalent: no
  conflicting value-votes observed (only value-vs-nil splits).
