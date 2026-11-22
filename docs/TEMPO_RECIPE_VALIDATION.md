# TEMPO_RECIPE_VALIDATION — 0.6s/block recipe in SIM (no live touch)

Date: 2026-11-02. Scope: SIM ONLY. No live nodes touched, no existing files
modified. New files only: `stellereum/tests/tempo_recipe_tests.rs` (this
suite) + this doc. Read: `docs/TEMPO_PROFILE.md`,
`docs/TEMPO_LOCAL_EVIDENCE.md`, `docs/PROPOSER_REWORK.md`,
`scripts/local-cluster.sh`, `stellereum/tests/block_tempo_lan.rs` (harness
idiom) + `stellereum/tests/sim_tempo_target06_tests.rs` (prior 250ms-link
recipe cell).

Question: does the 0.6s/block recipe (650ms base + 1500/1500/3000 straggler
grace) sustain sub-second finals in SIM on a 3-member instant-link cluster?

Short answer: **yes, in SIM on instant link, with large margin** — p50
150ms virtual, mean ~150–155ms virtual, max 150ms virtual, ~20–23k
finals/hour virtual, zero forks. This validates the TIMING only; the
WAN-only remainder list (§4) is what stands between this and any live claim.

## 1. Setup (SIM)

- Harness: `stellereum/tests/support/consensus_cluster.rs` (virtual clock,
  seeded xorshift PRNG, no wall clock in the protocol path). Real consensus
  code paths (propose/prevote/precommit/finalize, real signatures).
- Cluster: 3 validators, powers `[1,1,1]` (total 3, quorum 3 = unanimity),
  instant link (`inbound_delay_ms=0`, `propose_delay_ms=0` on all members),
  tick 50ms, base 650ms, `StragglerPolicy::fixed(1500, 1500, 3000)`.
- Seeds (deterministic): `0xC10C_0007` (sustained), `0xC10C_0008` (window +
  determinism), `0xC10C_0009` (stall pass). Reruns are fingerprint-identical.
- Each test runs < 120s wall (measured ~8.5s total for both tests, debug
  profile with optimized deps).

## 2. Recipe → sim mapping table

| recipe knob (production env) | sim param (harness-native) | status |
|---|---|---|
| `STELL_ROUND_TIMEOUT_MS=650` | `ConsensusCluster::build(3, profiles, seed, 50, 650)` base | mapped 1:1 (1 virtual ms = 1 wall ms on all timeout/delay paths) |
| `STELL_STRAGGLER_GRACE_MS=1500` | `StragglerPolicy::fixed(1500, …)` grace | harness-supported mechanism; production mapping = bounded additive hold outside the deterministic core (`docs/PROPOSER_REWORK.md` §2c) |
| `STELL_STRAGGLER_GRACE_CAP_MS=1500` | same policy cap | mapped 1:1 |
| `STELL_STRAGGLER_FRESHNESS_MS=3000` | same policy freshness | mapped 1:1 |
| `STELL_ROUND_ZERO_TIMEOUT_MS=650` (default) | harness round-0 cap `min(base*factor, 650)` in `step_round_timeout` | automatic, no knob to set |
| `STELL_TICK_MS=50` (default) | `tick_ms=50` | production default |
| instant link (loopback, zero delay) | `inbound=0` + `propose=0` all members | contrasts the 250ms-link recipe cell in `sim_tempo_target06_tests.rs`; topology matches `scripts/local-cluster.sh` loopback but NOT its timeouts |
| `STELL_BROADCAST_JOIN_MS=2000` / `STELL_CATCHUP_BUDGET_MS=8000` (local-cluster.sh defaults) | NOT modeled in-sim | WAN-only remainder (§4) |
| `scripts/local-cluster.sh` recipe applicability | NOT applied live here | script hardcodes `10000/2000/8000` into `run/cluster/node<i>/env.i` with no `STELL_STRAGGLER_*` passthrough (`docs/TEMPO_LOCAL_EVIDENCE.md` §2); env export before `up` is silently discarded. No script change per task constraints — SIM uses harness-native params above instead |

Env knobs are unsettable in-sim by design (the sim never reads process env
for timeouts except the legacy `SPD_FAST_FORWARD` override, left at default
ON here); the table above is the REPORT mapping required by the task.

## 3. Measured numbers (pasted `[sim]` lines, 2026-11-02)

Sustained (seed `0xc10c0007`, 80 heights after t=0 warmup):

```text
[sim][tempo-recipe][sustained] seed=0xc10c0007 heights=80 tick=50 base=650 grace=1500/1500/3000
[sim][tempo-recipe][sustained] virtual_total=14350ms mean=150.0ms p50=150ms p99=150ms max=150ms per_hour=20320 vc/final=0.05 grace=81
```

Window (seed `0xc10c0008`, 60 virtual s) + stall pass (seed `0xc10c0009`):

```text
[sim][tempo-recipe][window] seed=0xc10c0008 finals=385 per_hour=23100 mean_ms=155 vc/final=0.01
[sim][tempo-recipe][seedC] heights=20 max_dt=150ms bound=5000ms
```

Assertions pinned (all virtual-clock, no wall-clock asserts):

- Sustained: p50 150ms < 1000ms bar; mean 150.0ms <= 800ms bar; max 150ms
  <= 5000ms stall bound; 20320/h >= 4500/h (0.8s/block bar);
  `best - common = 0` (<= 1); 0.05 view-changes/final (<= 3.0).
- Window: 385 finals / 60 virtual s (23100/h >= 3000/h floor);
  `best - common = 0`; 0.01 vc/final; wasted share < 0.10 on all nodes.
- Safety: one hash per height (81/81 sustained, 385/385 window), zero
  double votes, state roots agree on all nodes.
- Determinism: identical rerun of seed `0xc10c0008` is
  fingerprint-identical; decide_rounds post-transient all 0 (first height
  delta 1 = virtual t=0 genesis transient, also present in `sim_happy3`).
- Straggler mechanism: policy ENABLED in all runs; grace engaged 81 ticks
  (sustained) / 81 ticks (window, 31+31+19 across nodes). On instant link
  the grace is insurance, not the rate driver (no skew to absorb) — the
  250ms-link grace-as-driver case is pinned separately by
  `sim_tempo_target06_tests.rs` (124 finals / 60 virtual s = 483ms/block
  at 250ms link) and `sim_proposer_straggler.rs` (0 → 1787 finals control
  vs fix).

Rate verdict for the suite gate: **sustained ~20.3k finals/hour virtual
(~150ms/block); window ~23.1k finals/hour virtual (~155ms/block)** —
both far inside the 0.6s/block recipe bar in SIM on instant link.

## 4. Honest WAN-only remainder list (NOT proven by this suite)

1. CPU/apply cost: sim advances ~0 virtual ms for build/verify/apply
   (signatures really verify; virtual time does not). In-tree anchors:
   loopback apply mean 66ms / p50 62ms / max 437ms, batch-verify 0.46ms
   per 20tx block (`docs/TEMPO_PROFILE.md` §§2.3,3). Live block ≈
   sim block + per-height CPU; the loaded 1-vCPU member's cost is
   UNMEASURED here.
2. Slow link: this suite is instant-link (0ms). The 250ms-link recipe cell
   (483ms/block) is `sim_tempo_target06_tests.rs`, not this file.
3. Slow ticks (5x timeout factor on a 1-vCPU member): not enabled here
   (all factors 1); covered by the straggler/proposer suites.
4. Join/catchup budgets (`STELL_BROADCAST_JOIN_MS`, `STELL_CATCHUP_BUDGET_MS`):
   no harness model; live 20s-quantum stalls are quantized by exactly these
   (`docs/TEMPO_LOCAL_EVIDENCE.md` §3b).
5. Network stack reality (retransmit, loss, partitions, asymmetric links):
   harness pump has fixed-order delivery + per-node delay only, no
   partitions; down-flag only.
6. Lock divergence / nil-storms: harness does not model lock-split nil
   persistence at 20s-scale timeouts (`docs/PROPOSER_REWORK.md` §4 limits).
7. Live-clock skew, restart-mid-run, mempool/execution backpressure: not
   modeled.
8. Real-binary confirmation at recipe env: blocked without a
   human-approved `local-cluster.sh` env-passthrough change
   (`docs/TEMPO_LOCAL_EVIDENCE.md` §5); defaults-only live data (p50
   ~0.25s, mean seconds, 20s-quantum stalls) does NOT transfer the sim
   rate to binaries.

## 5. Repro (SIM only, no live touch)

```text
cargo test --test tempo_recipe_tests -- --nocapture
cargo test -p stellereum --lib  # scope guard: 1067 passed, 0 failed (unchanged)
cargo clippy -p stellereum --all-targets -- -D warnings  # 0 warnings, 0 errors
```

No wall-clock assertions in the suite (wall time printed never asserted);
no live network use; deterministic seeds; virtual clock only.
