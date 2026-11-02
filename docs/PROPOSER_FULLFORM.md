# PROPOSER_FULLFORM — complete proposer logic, 0.6s/block budget, change list

Status: DESIGN ONLY. No code changed, no live ops, no restarts, no builds/tests.
Scope lock: this file only (`docs/PROPOSER_FULLFORM.md`).
Production consensus (`stellereum/src/consensus.rs`, `stellereum/src/runtime.rs`,
`stellereum/src/main.rs`) read-only for this task.

Context inputs read: `docs/PROPOSER_REWORK.md` (full, 320 lines),
`stellereum/src/consensus.rs` proposer/schedule paths,
`docs/TEMPO_PROFILE.md` (full, 217 lines). `docs/BFT_COMPARISON.md`
does NOT exist at time of writing — nothing below depends on it.
Operator goal: consensus "like other blockchains" — clean proposer rotation,
no restart/rewrite idiocy, brutal optimization toward 0.6s/block — while
keeping our tech (PQ/Falcon, downtime evidence, single-shard PARK).

Conventions: `file:line` = code TODAY (read-only). TEMPO = measured in
`docs/TEMPO_PROFILE.md` (loopback 3-node + virtual-clock sims). ESTIMATE =
author assumption where TEMPO has no number, labeled as such.

---

## 1. What "complete" proposer logic means — definition vs code TODAY

"Complete" = 7 sub-properties. Each defined, then what the code does TODAY.

### 1.1 Fair rotation

DEFINITION: every validator gets proposer slots proportional to its chance
to lead, with bounded wait between slots, identical schedule on all nodes,
computable locally for past + future (height, round).

TODAY: satisfied in mechanism. `ValidatorSet::proposer_for(height, round)`
(`stellereum/src/consensus.rs:1476`) computes
`BLAKE3("STELL_PROPOSER_V1" || height || round) mod (total/g)` over a
GCD-normalized cumulative power table with EXPLICITLY sorted ids
(`stellereum/src/consensus.rs:1454-1524`). Comment pins why: naive
`(height+round) % total` with real powers (e.g. 1874531430003/2e12/2e12,
gcd=1) gave the lexicographically-first validator every slot for ~1.9e12
heights (~60,000 years at 1 block/s) and parked the chain; hash-slot is
uniform over the whole power range from height 1, deterministic on every
node, statistically proportional to power. Lookahead inherent (same section).
Accessor `HeightConsensus::proposer()` (`stellereum/src/consensus.rs:3966`);
`ValidatorRuntime::is_proposer()` (`stellereum/src/runtime.rs:2674`).
Enforcement: `receive_proposal` (`stellereum/src/consensus.rs:3971`) refuses
wrong-proposer, one-value-per-round (equivocating proposer cannot overwrite),
idempotent rebroadcast Ok. `proposer_missed_streak`
(`stellereum/src/consensus.rs:4750`), `note_proposer_missed`
(`stellereum/src/consensus.rs:4738`), `PROPOSER_MISS_THRESHOLD_M = 3`
(`stellereum/src/consensus.rs:3859`) track per-validator misses;
`missed_proposals_total` + `inc_proposer_miss` metrics
(`stellereum/src/metrics.rs:1013`).

Gap (not in mechanism, in outcome): under 3/3 unanimity the schedule is
fair but USELESS — every veto rung still costs a full timeout ladder
(TEMPO §2.2: per-rung dwell ~20.0s, §2.1: 17 stalls/162 heights = 88.2% of
span). See §2 gaps G1/G2.

### 1.2 Stake-weighting

DEFINITION: P(slot) ∝ voting power, exact for integer ratios, statistically
exact for arbitrary powers, no container-order dependence.

TODAY: satisfied. GCD normalization keeps 2:1 exactly B,B,A while rotating
from h=1 (`stellereum/src/consensus.rs:1454-1461`); hash-slot keeps
weighting statistically exact for coprime powers; explicit `sort_unstable`
(`stellereum/src/consensus.rs:1514-1515`) removes `BTreeMap`-order
dependence (audit-consensus F8 comment: unsorted walk elected DIFFERENT
proposers per node — 1/9 agreement with 3 nodes — and halted the chain).
`quorum_power = floor(2*total/3)+1, empty set = u64::MAX (never quorums)`
(`stellereum/src/consensus.rs:1389-1406`); `qc_meets_quorum`
(`stellereum/src/consensus.rs:1442`), `qc_signed_power`
(`stellereum/src/consensus.rs:1431`). Quorum-safety log gate for 100%-power
sets (`stellereum/src/main.rs:1080-1089`,
`stellereum/src/staking.rs:655` `validator_powers_fragility`).

### 1.3 Lookahead

DEFINITION: any node can name the proposer of (h, r) and (h+1, 0) without
network traffic, early enough to prebuild / pre-fetch.

TODAY: satisfied. Schedule is a pure function of (height, round) — no
beacon, no messages (`stellereum/src/consensus.rs:1470-1473`). Consumers:
VEL-1 prebuild targets `proposer_for(h+1, 0) == self.id`
(`stellereum/src/runtime.rs:2910`); same-tick fast-forward gates on
`is_proposer && has_prebuild_for(h)` (`stellereum/src/main.rs:5990-5995`).
`PROPOSAL_ALIGN_WINDOW_ROUNDS = 8` (`stellereum/src/runtime.rs:75`) bounds
the early-delivery acceptance window for future-round proposals
(`stellereum/src/runtime.rs:5682-5691`).

### 1.4 Proposal timeliness rules

DEFINITION: a proposal is accepted iff (a) correct slot, (b) correct height,
(c) timestamp-valid, (d) builds on known state, (e) signed by the slot owner —
with NO wall-clock veto that can split honest nodes.

TODAY: satisfied, and deliberately wall-clock-free:
- (a) `receive_proposal` wrong-proposer refusal
  (`stellereum/src/consensus.rs:3979`); round-independence split:
  `validate_proposal_unaligned` proves genuineness BEFORE round alignment so
  a forged envelope cannot shove +64 rounds
  (`stellereum/src/runtime.rs:4860-4866`).
- (b) wrong-height refusal (`stellereum/src/runtime.rs:4871`).
- (c) `check_block_timestamp` (`stellereum/src/runtime.rs:4612`): monotone
  vs parent timestamp, at most `MAX_TIMESTAMP_JUMP_SECS = 3600` ahead
  (`stellereum/src/runtime.rs:62`, enforced at `:4350`, `:4653`).
  Explicitly NO `now_secs()` bound — comment at
  (`stellereum/src/runtime.rs:4874-4883`): a wall-clock bound makes two
  validators with skewed clocks disagree about the same block.
- (d) `state_root == expected_state_root` else LOUD DIVERGENCE + refusal
  (`stellereum/src/runtime.rs:5014-5044`); shard-head + epoch-MMR + order
  commitments (`:5050`, `:5052`, `:5059-5072`); canonical downtime evidence
  `check_last_qc_evidence` (`:5073-5077`); `MAX_BLOCK_TXS`
  (`stellereum/src/runtime.rs:27`) / `MAX_BLOCK_GAS`
  (`stellereum/src/runtime.rs:51`) caps enforced at `:5111`, `:5131`
  (and `:7660`, `:7667` second path).
- (e) proposer-signature verify with Falcon-aware path + verify-once cache
  (`stellereum/src/runtime.rs:5078-5089`,
  `stellereum/src/consensus.rs:393-445`).
- Liveness gates around timeliness (not validity): DOWN-PROPOSER fast
  timeout 800ms default (`stellereum/src/main.rs:135-148`), deterministic
  predicate on ledger `missed >= DOWNTIME_MISS_THRESHOLD (10)`
  (`stellereum/src/main.rs:1076-1078`, `stellereum/src/staking.rs:238`),
  actuator (`stellereum/src/main.rs:6134-6157`); round-0 cap 650ms
  (`stellereum/src/main.rs:150-157`, actuator `:6158-6161`); straggler
  grace additive hold, default-off
  (`stellereum/src/main.rs:159-243`, actuator `:6165-6209`,
  `cap_hold_to_two_x_bound` at `:260`); peer-active 2× hold
  (`stellereum/src/main.rs:6090-6100`).

What "complete" ADDS here: nothing in validity — the validity side is done.
The gap is all in the TIMING side (§2 G3–G5).

### 1.5 Empty-block policy

DEFINITION: explicit rule for when a proposer may/must propose an empty
block vs wait for transactions, plus a flood guard.

TODAY: empty blocks ALLOWED, never refused; flood guard is a time floor,
not a content rule. `DEFAULT_MIN_BLOCK_MS = 50`
(`stellereum/src/main.rs:980`), env `STELL_MIN_BLOCK_MS` (0 disables)
(`stellereum/src/main.rs:3668-3674`), enforced at propose gate
(`stellereum/src/main.rs:4452`), prebuild gate (`:4476`), fast-forward gate
(`:5994`), with `last_block_at` bookkeeping (`:3674`, `:4012`, `:5963`).
Rationale comment (`:969-980`): 400→50ms change 2026-10-26, live fleet
already ran 50ms via env, 50ms caps empty blocks at 20/s vs unbounded
without guard; pinned by `floors_pinned_until_live_remeasurement`
(`stellereum/src/main.rs:10273`). Fast-forward comment notes empty blocks
hit trivially (`:5986-5987`). No `txs.is_empty()` refusal anywhere in the
propose/validate paths (verified by grep — refusals are height/shard/
root/signature/cap-based only).

"Complete" verdict: policy EXISTS and is correct for tempo (floor, not ban).
No change needed for 0.6s (empty fast path is the fastest path).

### 1.6 Mempool packing

DEFINITION: deterministic, fee-ordered, cap-respecting selection with
bounded cost on the propose critical path, revalidated against live state.

TODAY: satisfied functionally, optimized already:
- Selection: `Mempool::select` highest-fee (`stellereum/src/mempool.rs:2371`),
  `select_bounded` (`:2383`), `select_for_block_multi` 64-way sharded
  (`:2454-2458`), wire/proof caps `MAX_BLOCK_WIRE_BYTES = 24MB` (`:740`),
  `MAX_BLOCK_PROOF_UNITS = 2048` (`:745`), enforced during select
  (`:2517`, `:2521`).
- Propose: `ValidatorRuntime::propose` (`stellereum/src/runtime.rs:3441`):
  locked-reproposal path (`:3481-3510`), demanded-reproposal path
  (`:3511-3570`, `MAX_DEMANDED = 8` at `:5403`), fresh path with
  `pack_snapshot` sender-state cache (`:3592-3600`), `pack_filter_accept`
  (`:2719`), caps `MAX_BLOCK_TXS = 10_000` / `MAX_BLOCK_GAS = 500M`
  enforced (`:2857-2860`, `:3723`, `:3881-3907`).
- Prebuild (VEL-1): `prebuild_next_proposal` runs selection during prevote
  idle (`stellereum/src/runtime.rs:2902-2942`), `has_prebuild_for` gate
  (`:2873-2879`), revalidation + top-up in `propose` preserves validity.
- Measured (main.rs budget comment `:982-1026`, TEMPO §3): packing ~41ms
  cold / ~11ms warm (sender snapshot), validation ~164ms/loaded-proposal
  (single-validation fast path removes repeat), apply ~16ms/428-tx block,
  CPU probes `batch_verify_20tx = 0.462ms`, `order_commit_20tx = 0.011ms`
  (TEMPO §3).

"Complete" verdict: packing is complete. Remaining work is all to KEEP it
off the critical path (§4 C2), not to redesign it.

### 1.7 Downtime evidence + single-shard PARK (kept tech)

DEFINITION (operator constraint): keep PQ/Falcon, downtime evidence,
single-shard PARK behavior untouched while chasing tempo.

TODAY (frozen, see §5): Falcon-512 vote envelopes
(`stellereum/src/consensus.rs:328-476`, `VOTE_FALCON_MAGIC/PART_LEN`
`:329-331`, `sign_with_falcon` `:1811`, verify `:1655-1669`), PQ micro/epoch
envelopes (`:470-877`, `QC_PQ_MAGIC` `:486`), proposer Falcon path
(`:393-445`); canonical downtime evidence `check_last_qc_evidence`
(`stellereum/src/runtime.rs:5073-5077`), ledger `missed` streaks
(`stellereum/src/staking.rs:685-742`, threshold 10 at `:238`); single-shard
default preserved (`stellereum/src/sharding.rs:377-423`, `:2324`,
`:5983`; `is_sharded()` gates in runtime/main).

---

## 2. Gap list vs the definition (ranked by 0.6s-block impact)

G0 is the load-bearing gap; G1–G3 are the timed-mechanism gaps; G4–G6 are
small but cheap. All ranks assume the operator's 0.6s/block target under a
250ms slowest member (PROPOSER_REWORK §1 ground truth).

- **G1 — Unanimity veto multiplier (QUORUM/TOPOLOGY, not proposer code).**
  3 validators, total power 3, quorum 3: ANY single split stalls (TEMPO §1:
  `(2n+1)/3+1 = 3` forces unanimity; PROPOSER_REWORK §1: 20s base, ~1 QC/5min).
  TEMPO loopback (ZERO network delay): 162 common heights over 565.0s, of
  which **88.2% (498.3s) is ≥5s stalls, 17 events** (TEMPO §2.1); per-rung
  dwell **~20.0s ≈ 2× configured 10s base** (TEMPO §2.2); decide follows in
  **0.14–0.50s** once rotation reaches an acceptable proposer. Stall anatomy
  (TEMPO §2.5): sync-jump over undecided height + stale lock → member
  prevotes nil on its own proposal while others finalize it → unanimity QC
  impossible until rotation + higher-round justification. No proposer-code
  change fixes arithmetic: 2/3 < 3. Rank 1 by span share alone.

- **G2 — Slow-link desync probability (same multiplier, WAN shape).**
  250ms home link + 1-vCPU slow ticks (PROPOSER_REWORK §1) raise desync
  probability; each desync costs the G1 rung price (~20s effective). TEMPO
  WAN sim (delays 80/120/180/250ms, timeout 3500): 640ms mean / 650 p50 /
  700 p99 WITH 2/3-quorum 4-node and all fixes ON (TEMPO §3) — i.e. even the
  FIXED stack sits at the 0.6s edge under WAN physics; under 3/3 the same
  physics pays veto rungs instead of milliseconds. Fix is topological
  (4th validator → 3/4 tolerates one desynced; or move slow link), not a
  faster proposer.

- **G3 — ~1s vote-late events (CONSENSUS/SYNC path, ~7% of span).**
  31/162 heights take 1–5s (38.7s, 6.9% of span; TEMPO §2.1); shape:
  proposal instant (often same-tick fast-forward, e.g. +6ms), votes
  **~965–1070ms late**, decide+apply normal (~130ms), all r0 (TEMPO §2.4).
  1:1 correlation with `[sync] fetch_block_qc … failed` lines — ESTIMATE:
  one backoff/timeout rung in vote gossip or sync-prefetch racing consensus.
  At 0.6s/block, a ~1s event on ~19% of heights single-handedly breaks the
  mean even with zero veto stalls.

- **G4 — Round-timer 2× accounting (TIMER, doubles every stall, taxes grace).**
  Gate fires at `max(effective, 2 × base)` while a peer is active
  (`stellereum/src/main.rs:6099-6100`); TEMPO §5.3 names it the 20s-vs-10s
  root cause (ESTIMATE: timer reset on vote/proposal activity). Effect:
  halves the value of every stall fix; unsubsumed grace stacks PAST the 2×
  bound (`effective + grace`) instead of filling it — mitigated ONLY by
  `cap_hold_to_two_x_bound` (`stellereum/src/main.rs:260`,
  applied at `:6204-6207`). Still costs one extra rung of waiting per stall
  on dead peers (2× window releases after two timeouts).

- **G5 — Round-0 propose wait 650ms > 600ms budget.**
  `round_zero_timeout_ms` default 650ms (`stellereum/src/main.rs:150-157`),
  applied when `!has_live_proposal && round == 0` (`:6158-6161`). On a
  healthy r0 the proposal lands in ms (TEMPO §2.3: 10–160ms to quorum
  prevotes; §2.4: +6ms fast-forward case), but the CAP is the budget: any
  r0 that actually waits the cap (slow 1-vCPU build, 700/900ms slow
  proposers in VEL sim TEMPO §3) exceeds 0.6s before voting starts. VEL
  AFTER absorbs slow builds via prebuild+fast-forward (0 extra rounds with
  700/900ms propose delays), but that depends on the prebuild HIT — on a
  miss the 650ms cap is the floor.

- **G6 — Tick quantization + retransmit waste (small, bounded).**
  `TICK_MS = 50` (`stellereum/src/main.rs:1243`); happy path needs
  propose+prevote+precommit+finalize ticks (budget comment `:993-994`);
  fast-forward saves one tick per height (`:5966-5973`). Residual
  `grace_extends` waste traced to view-change retransmit path
  (PROPOSER_REWORK §4: stale arrivals 1.000→~0.53, waste 1.000→~0.063 —
  residual is laggard mid-height timeout + proposalless-bucket votes, not
  countable). Each tick/round-trip is 50ms = 8.3% of the 600ms budget —
  worth one tick, never a rewrite.

- **G7 — Missing observability-to-action loop (OPERATIONAL, not consensus).**
  Signals exist (`straggler_grace_extends_total`
  `stellereum/src/metrics.rs:89,517-518,968-973`; `proposer_miss`
  `:1013`; `validator_set_{size,power,quorum,fragile}` `:104-111`;
  finalize-blockers `finalize_blockers()` at main `:6025`; DIVERGENCE tag
  at runtime `:5032`). Gap: no schedule-aware alerting (slow-proposer slot
  cost), no p99 vote-lag-per-member dashboard from RX logs (PROPOSER_REWORK
  §5.5 tuning input), no auto-avoidance of the 250ms member's slots.
  Zero ms saved directly; unlocks every other fix's tuning.

NOT gaps (explicitly): rotation fairness (§1.1), stake-weighting (§1.2),
lookahead (§1.3), proposal validity/timeliness (§1.4), empty-block rule
(§1.5), packing correctness (§1.6) — all complete TODAY.

---

## 3. 0.6s/block budget breakdown (600ms)

Method: TEMPO numbers where measured; ESTIMATE labeled otherwise. Slowest
member 250ms one-way (PROPOSER_REWORK §1: B on 250ms+ link). Target = r0
happy path mean ≤600ms; p99 ≤600ms needs G1–G3 closed (below).

### 3.1 Where the milliseconds go (r0 happy path, WAN)

| Phase | ms | Source / status |
|---|---|---|
| Propose-build (proposer-local, critical path) | 0–11 | TEMPO §3 + main `:982-1026`: 41ms cold / 11ms warm; VEL-1 prebuild moves it OFF-tick (runtime `:2902`). MUST stay off-tick: 41ms = 6.8% of budget on miss. Prebuild HIT assumed (G5 covers miss). |
| Proposal propagation P2P (one-way to 250ms member) | ~250 | ESTIMATE (physics of the 250ms link; TEMPO WAN sim uses 250ms max delay and totals 640ms mean — consistent). CANNOT be reduced by code; must be OVERLAPPED, not waited out sequentially. |
| Vote collection (slowest prevote inbound, overlapped with gossip fan-out) | +0–50 beyond propagation | TEMPO §2.3 loopback: proposal→quorum-prevotes 10–160ms; TEMPO §3 WAN: total 640ms with 250ms max delay PROVES overlap (sequential 250+250+250 would exceed 700ms mean). Vote-fan-in + pipeline REQUIRED (§4 C2). |
| Precommit QC (quorum-prevotes→DECIDED) | 13–130 | TEMPO §2.3 measured. Can stay. |
| Finalize/apply (DECIDED→FINALIZED) | mean 66, p50 62, max 437 | TEMPO §2.3 (n=99). Can stay on average; max 437ms = 73% of budget — §7 Phase-2 sequenced worker already moves apply OFF-tick (main `:5966-6017` comment, runtime `apply_in_flight` gate `:3454`). MUST keep off-tick. |
| Tick quantization (propose/prevote/precommit/finalize ticks) | 50–100 (1–2 × `TICK_MS = 50`) | `stellereum/src/main.rs:1243`. Fast-forward saves 1 tick/height (`:5966-5973`). Keep; do not lower TICK without re-measurement (budget comment `:982`). |
| Validation CPU per proposal (receivers) | <1–36 | TEMPO §3: `batch_verify_20tx 0.462ms`, `order_commit 0.011ms`; main `:1003-1007`: loaded 1785-tx ~164ms → ~36ms single-validation fast path (~5× on 1-vCPU). Negligible at minimal-tx tempo; binding only for fat shielded blocks (packing caps bind first). Can stay. |
| **Happy-path total (warm prebuild, overlapped network)** | **~380–540** | Arithmetic: 11 (build) + 250 (propagation) + 30 (vote overlap margin) + 70 (precommit mid) + 66 (apply mean) + 50 (1 tick net after ff) ≈ 477ms. Headroom ~120ms to 600ms. Consistent with TEMPO WAN AFTER 635.5ms mean / 650 p50 (that sim ADDS 700/900ms slow-proposer builds, absorbed by prebuild — without slow builds the same stack is LAN 300ms mean). |

### 3.2 What the arithmetic PROVES must change vs can stay

MUST change (else 600ms impossible even with perfect happy path):
1. **Veto rungs must go (G1/G2).** One rung = ~20s effective (TEMPO §2.2) =
   **33× the entire 600ms budget**. 17 such events = 498.3s = 88.2% of span
   (TEMPO §2.1). No per-phase optimization (even 0ms build + 0ms apply)
   covers a 20,000ms rung. ⇒ Topology/quorum fix (4th validator or
   equivalent) is the ONLY change with enough gain; everything else is
   rounding until this closes. (TEMPO §5.1: 4-node 2/3 sim = 0 view changes
   in 300 heights WITH 700/900ms slow proposers vs 17 stalls/162 heights
   loopback 3-node with NO delay.)
2. **~1s vote-late events must go (G3).** 965–1070ms late votes (TEMPO §2.4)
   = **1.6–1.8× the budget** on ~19% of heights, all r0. Mean with 19% ×
   1s events: `0.81 × 450 + 0.19 × 1100 ≈ 573ms` — at the edge BEFORE any
   p99 or stall; any regression pushes over. ⇒ Decouple `fetch_block_qc`
   miss path from consensus vote delivery (or prove which side blocks).
3. **Round-0 cap 650ms must shrink-or-hit-always (G5).** 650 > 600 by
   construction. Either the prebuild HIT rate must be ~100% (so the cap
   never binds) or the cap must drop to ≤150–200ms with DOWN-PROPOSER
   backstop intact. ESTIMATE: 150ms cap + 800ms down-proposer escape covers
   both slow-but-live (prebuild absorbs) and down (fast timeout) cases.

Can stay (proven ≤ budget by TEMPO):
- Apply path (~66ms mean), batch verify (0.5ms), order commit (0.01ms),
  packing warm (~11ms), proposal fan-in (~100ms loopback) — TEMPO §5.5:
  each <0.1% of live tempo; sum < 1/3 of 600ms budget.
- Empty-block floor 50ms (8.3% of budget) — keep as flood guard.
- TICK_MS 50ms — keep; fast-forward already banks the savable tick.
- Deterministic timeout CORE values (base + 500/round + 500/miss) — keep;
  fix ACCOUNTING (2× hold) and GRACE subsumption, not the ladder.

p99 note: TEMPO WAN p99 700ms / max 700ms (20 heights) and VEL AFTER p99
700ms (TEMPO §3) show even the FIXED 2/3 stack exceeds 600ms at p99 under
WAN physics. 0.6s/block MEAN is achievable with G1–G5 closed; 0.6s p99
additionally needs either (a) slow-member slot avoidance (topology-aware
scheduling is NOT fair-rotation — see §5 for why it stays OUT), or (b)
accepting p99 ≈ 700ms as physics. Do not chase p99 with consensus-code
complexity — that way lies (b)-class unsafety (PROPOSER_REWORK §2b).

---

## 4. Concrete change list (ordered by gain/risk)

Each item: area (`file:line`), expected ms saved, safety argument (one
paragraph). All timing-only unless marked TOPOLOGY. No frozen-core touch
(§5). Straggler grace already behind env (PROPOSER_REWORK status line +
`STRAGGLER_GRACE_MS_DEFAULT = 0` at `stellereum/src/main.rs:178`) — C1
tunes/deploys it, does not invent it.

- **C1 — Deploy/tune straggler grace (already in production, default-off).**
  Area: `stellereum/src/main.rs:159-243` (`straggler_hold_ms`),
  `:6165-6209` (actuator + `cap_hold_to_two_x_bound` at `:260`),
  `stellereum/src/metrics.rs:968-973` (`inc_straggler_grace_extends`),
  evidence `note_peer_round` (`stellereum/src/consensus.rs:4818`),
  `supporting_peers_count` (`:4826`), `max_peer_round` (`:4852`).
  Expected: sim-measured stall-rate collapse 0 → 1787 finals/20 virtual-min
  (5361/virtual-hour), waste 1.000 → ~0.063 (~16×), slow-member jumps
  5969 → 1 (PROPOSER_REWORK §4); live translation ESTIMATE: converts each
  slow-member r0/r1 from a 20s veto rung into a ≤cap hold (tuning start:
  grace ≈ 2× slowest vote latency, cap = grace, freshness ≈ 5–10× base per
  §5.5). Gain: seconds-to-minutes per stall (largest code-side lever left);
  risk: LOW (default-off today, additive, self-expiring).
  Safety: timing-only — vote content, validity, per-(height,round,kind)
  bucketing, quorum arithmetic (`quorum_power` at `:1389`, `quorum_target`
  at `:2477`), lock rules (`decide_prevote` at `:4008`,
  `try_precommit_quorum` same-round agreement + lock refusal at
  `:4460-4472`), QC verification (`qc_meets_quorum` at `:1442`), and the
  proposer schedule are all untouched; heterogeneous holds cannot fork
  because Tendermint safety is time-free and the grace only ever widens
  honest-round overlap, with dead peers aging out via freshness so only a
  live-but-slow member buys time (PROPOSER_REWORK §2c, sim pins no fork /
  no double-votes / state-root agreement).

- **C2 — Escape 3/3 unanimity: 4th validator (TOPOLOGY, no consensus code).**
  Area: validator-set derivation / staking powers
  (`stellereum/src/staking.rs:655` fragility,
  `stellereum/src/main.rs:1080-1089` `log_quorum_safety`,
  `stellereum/src/consensus.rs:1389-1444` quorum math — READ, do not edit).
  Expected: removes the veto-stall class = **~88% of loopback span**
  (TEMPO §5.1); 4-node 2/3 sim = 0 view changes/300 heights with 700/900ms
  slow proposers. Gain: minutes per stall window; risk: LOW-OPERATIONAL
  (1 host + keygen, coordinated epoch change — no code, no wire change).
  Safety: this is the SAFEST change precisely because it touches no
  consensus rule — quorum stays `floor(2n/3)+1` (3/4 tolerates one
  desynced/slow instead of 3/3 tolerating zero); the fragile-set warning
  already names the disease, the 4th member cures the arithmetic the
  warning complains about; rollback is key-removal via the normal staking
  path, never a state migration.

- **C3 — Decouple the ~1s vote-late path (`fetch_block_qc` miss vs vote gossip).**
  Area: `stellereum/src/main.rs:1752`, `:2104` (`fetch_block_qc` callers),
  `stellereum/src/runtime.rs` sync-prefetch path, vote-gossip delivery
  (`MAX_INBOUND_PER_TICK = 512` at main `:1248`,
  `INNER_BUDGET_PER_TICK` at `:4702`). Expected: −965–1070ms on ~19% of
  heights (31/162 mid bucket, 6.9% of span — TEMPO §2.4); mean −~190ms at
  current mix, and removes the single biggest r0-only 0.6s-budget breaker.
  Gain: ~200ms mean / ~1s on affected heights; risk: LOW-MEDIUM (needs the
  1:1 correlation proved causal first — instrument which side blocks).
  Safety: delivery/ordering-only — whichever side is fixed (prefetch
  timeout shortened/decached, or vote path prioritized over sync fetch),
  vote CONTENT, bucketing, quorum counting, lock rules, and QC verification
  are untouched; the worst case of a wrong fix is preserved 1s latency
  (fail-open to today's behavior), never a fork, because no counting rule
  or validity predicate changes.

- **C4 — Make the round timer absolute (fix 2× accounting).**
  Area: `stellereum/src/main.rs:6090-6100` (`hold_bounded` 2× gate),
  `:6204-6207` (`hold_slack` cap), `deterministic_timeout_for` at
  `:1064` + `deterministic_round_timeout_ms`
  (`stellereum/src/consensus.rs:3891-3903`, backoff 500/round cap 10k at
  `:3834-3840`, adaptive 500/miss cap 5k at `:3847-3853`).
  Expected: halves every stall rung 20s → ~10s (TEMPO §2.2: 8 rungs
  19.18–20.75s vs 10s configured; §5.3: up to −50% of stall dwell, stalls
  remain). Gain: ~10s per veto rung (second-largest after C1/C2
  combined); risk: LOW (timer-only, already partially mitigated by the
  `hold_slack` cap — this completes that job).
  Safety: timing-only — the deterministic timeout VALUE stays a pure
  function of (base, round, ledger-missed) identical on all nodes, and the
  change only removes the ACTIVITY-reset that makes the EFFECTIVE rung 2×
  the value; view-changes still fire, votes still count identically, locks
  and quorums untouched, and the 2×-window leapfrog analysis in the
  surrounding comment is preserved by keeping a bounded (not unbounded)
  peer-active hold so a silent peer still releases after a fixed bound.

- **C5 — Shrink-or-never-bind the round-0 propose wait.**
  Area: `round_zero_timeout_ms` (`stellereum/src/main.rs:150-157`, default
  650), actuator at `:6158-6161`, prebuild HIT gate
  (`stellereum/src/runtime.rs:2873-2879`, `:2902-2942`), fast-forward
  (`stellereum/src/main.rs:5966-6017`), DOWN-PROPOSER escape
  (`:6134-6157`, threshold `stellereum/src/staking.rs:238`).
  Expected: up to −500ms on slow-proposer r0s that bind the cap today
  (650ms cap → 150–200ms cap = −450–500ms; prebuild HIT already avoids the
  wait entirely on hits — VEL AFTER 0 extra rounds with 700/900ms builds).
  Gain: 50–500ms on affected r0s (the margin between 650ms cap and 600ms
  budget); risk: LOW (cap-only + prebuild-coverage metric; DOWN-PROPOSER
  fast path unchanged as backstop).
  Safety: timeout-only — the cap moves OUR round, never the chain; a
  merely-slow proposer's proposal still seats `has_live_proposal`
  (`stellereum/src/consensus.rs:4002`) and wins the race toward waiting
  (normal backoff), while a proven-down proposer (ledger missed ≥ 10,
  identical on all nodes) still gets the 800ms fast path; no vote content,
  validity, or quorum rule changes, so heterogeneous caps cannot fork.

- **C6 — Keep VEL-1 prebuild + fast-forward + pipeline ON and pinned (no rewrite).**
  Area: `prebuild_next_proposal` (`stellereum/src/runtime.rs:2902`),
  `has_prebuild_for` (`:2873`), `pack_snapshot` (`:783`),
  `pack_filter_accept` (`:2719`), fast-forward
  (`stellereum/src/main.rs:5966-6017`), pipeline isolation (TEMPO §3:
  634.2 vs 684.2ms ≈ 50ms/height, 7%). Expected: already-banked −63% mean
  in-sim (1745→636ms, 760→0 extra rounds — TEMPO §3); going forward SAVES
  ~50ms/height (one tick) + absorbs 700/900ms slow builds that would
  otherwise each cost a full ladder round. Gain: 50ms sustained + seconds
  on slow slots; risk: LOWEST (already in production, liveness-only).
  Safety: proposer-local liveness-only — no wire bytes, no quorum input, no
  state transition; `propose` revalidates every cached tx against LIVE state
  through the SAME predicate and tops up, so a changed parent only shrinks
  or refreshes reuse (validity by construction), and the fast-forward
  reuses the identical top-of-tick gates (can_vote, no pending apply,
  is_proposer, `!has_live_proposal`, `min_block_time`, same parent/head/
  root, idempotent via self-record) — earlier proposals only improve
  liveness because timeouts never move safety.

- **C7 — Schedule-aware ops loop (dashboard + slot-cost accounting, no consensus change).**
  Area: metrics already emitted (`straggler_grace_extends_total`,
  `proposer_miss`, `validator_set_*` at `stellereum/src/metrics.rs:89-111,
  517-567,968-1014`), RX-log vote-lag per member (PROPOSER_REWORK §5.5),
  `finalize_blockers()` (main `:6025`), `proposer_for` lookahead
  (`stellereum/src/consensus.rs:1476`). Expected: 0ms directly; unlocks C1
  tuning (grace ≈ 2× p99 vote lag) and proves/retires C3 causality.
  Gain: enables all others; risk: NONE (observability only).
  Safety: read-only — new dashboards/alerts consume existing counters and
  logs; no vote, quorum, apply, mempool, staking, or signature path is
  touched, so there is no fork, stall, or spec-fork surface by construction.

Explicit non-goals in this list: vote-forwarding across rounds (rejected
unsafe with proof — PROPOSER_REWORK §2b; breaks same-round agreement at
`try_precommit_quorum` `:4460-4472` and lock at `:4468-4472`); pure
scheduled-proposer stickiness without behind-vote clause (covers only ~1/3
of stalls — §2a); re-serve/retransmit alone (rate-blind — §2d).

---

## 5. What explicitly NOT to change (frozen core + rationale)

Per `AGENTS.md` §7 (frozen core) and the safety arguments above. Each item:
what, where, why touching it risks the chain for ~zero 0.6s gain (TEMPO
measured negligible or safety-load-bearing).

1. **Wire format / consensus message envelope.** Votes, proposals, QCs,
   µQC/epoch envelopes (`stellereum/src/consensus.rs:470-877`,
   `QC_PQ_MAGIC`, `PQ_UQC_MARKER_ID`), outbox/large-message paths
   (`stellereum/src/main.rs:6007-6012`). Rationale: any byte change is a
   spec fork requiring coordinated upgrade + audit note; TEMPO proves
   broadcast is NOT binding at minimal-tx sizes (60KB/500 txs ≪ caps).
2. **Quorum values / counting rules.** `quorum_power`
   (`stellereum/src/consensus.rs:1389`), `quorum_target` (`:2477`),
   `quorum_reached` (`:2472`), `qc_meets_quorum` (`:1442`),
   per-(height,round,kind) bucketing (`prevotes`/`precommits` maps at
   `:3917-3918`, `add_prevote` scope gate `:4028-4039`), same-round
   prevote+precommit agreement + lock refusal (`:4460-4472`), one-vote
   invariant. Rationale: counting IS safety — PROPOSER_REWORK §2b proves
   cross-round counting forks; TEMPO proves counting costs nothing
   (sub-ms CPU).
3. **`apply()` / execution / state transition.** `poll_apply`,
   `has_pending_apply`, `apply_in_flight` gates
   (`stellereum/src/runtime.rs:3454`, `stellereum/src/main.rs:5991`),
   sequenced Phase-2 worker. Rationale: post-state divergence already
   observed live (#288000, runtime `:5015-5044` DIVERGENCE witness);
   touching apply risks consensus-safety splits for ~66ms mean gain that is
   already off-tick.
4. **Mempool admission / packing predicates.** `pack_filter_accept`
   (`stellereum/src/runtime.rs:2719`), `select_for_block_multi` caps
   (`stellereum/src/mempool.rs:2434-2521`), `MAX_BLOCK_TXS/GAS/WIRE/PROOF`
   (`runtime.rs:27,51`; `mempool.rs:740,745`). Rationale: admission is
   DoS-resistance + determinism; TEMPO proves warm packing ~11ms — not
   binding. Tune prebuild COVERAGE (C6), never the predicate.
5. **Staking math / powers / fragility definition.** `DOWNTIME_MISS_THRESHOLD
   = 10` (`stellereum/src/staking.rs:238`), `validator_powers_fragility`
   (`:655`), `REENTRY_LIVENESS_WINDOW_HEIGHTS` (`:689`), ledger `missed`
   streaks. Rationale: powers ARE the schedule and quorum inputs
   (deterministic on all nodes); changing math mid-epoch forks the
   schedule (`proposer_for` `:1476` diverges) — add members (C2), don't
   redefine power.
6. **Signature domains (Ed25519 / Falcon / BLS envelopes, chain-id binding).**
   `VOTE_FALCON_MAGIC/PART_LEN` (`stellereum/src/consensus.rs:329-331`),
   `verify_falcon_signature` (`:374`), `attach_vote_falcon` (`:448`),
   proposer Falcon path (`:393-445`), `consensus_chain_id` frozen
   (`:63-69`), chain-binding activation. Rationale: domain change unbinds
   replay protection (testnet↔mainnet) and invalidates in-flight QCs;
   verify cost sub-ms (TEMPO CPU probe) — zero tempo gain, total safety
   loss.
7. **Proposer schedule function itself.** `proposer_for`
   (`stellereum/src/consensus.rs:1476`), GCD+hash-slot, sorted-id walk.
   Rationale: CONSENSUS CHANGE by its own comment (`:1474-1475`) — old
   nodes compute a different schedule; deploy only coordinated. It is
   already fair + weighted + lookahead-complete (§1.1–1.3); slot-AVOIDANCE
   of the slow member (tempting for p99) would trade fairness for
   centralization and reintroduce the лексик-first starvation class the
   hash-slot fixed. Fix topology (C2), not the function.
8. **Lock rules / fork-choice.** `locked: Option<(BlockHash, Round)>`
   (`:3248`), `decide_prevote` lock arm (`:4008-4021`),
   `try_precommit_quorum` lock refusal (`:4468-4472`), polka ledger
   (`:4051-4059`), `prune_old_rounds` retention (`:4566-4575`).
   Rationale: locks ARE the "no two conflicting decides" proof; TEMPO §2.5
   shows stalls RESOLVE via higher-round justification unlocking — weakening
   locks turns stalls into forks.
9. **Single-shard PARK behavior.** `STELL_SHARDS` unset default
   (`stellereum/src/sharding.rs:379-423`), `is_sharded()` gates, shard-scope
   validation skip in single-shard mode (`runtime.rs:4890-4891`). Rationale:
   operator constraint; sharding paths add cross-shard proof/anchor costs
   with zero 0.6s benefit on the current single-shard fleet.
10. **TICK_MS / MIN_BLOCK_MS floors (values).** `TICK_MS = 50`
    (`stellereum/src/main.rs:1243`), `DEFAULT_MIN_BLOCK_MS = 50`
    (`:980`). Rationale: floors are flood guards, already at the TEMPO-
    remeasured minimum (400→50ms with live fleet evidence); lowering TICK
    further buys <50ms at unbounded CPU/wake risk — the budget comment
    (`:982-1026`) forbids change without a loaded-height re-measurement.

---

## Appendix — traceability (read-only sources)

- Rotation/weighting/lookahead: `stellereum/src/consensus.rs:1357-1525`
  (set + `proposer_for`), `:3966` (accessor), `:3971-4004`
  (receive/live-proposal), `:4008-4026` (prevote/precommit decide).
- Timing core: `:3833-3903` (backoff/adaptive consts + deterministic fn),
  `:4516-4538` (`sync_round_to`), `:4818-4854` (peer rounds),
  `:4856-4929` (deadlock breaker); `stellereum/src/main.rs:130-262`
  (down-proposer + straggler + round-zero fns), `:964-1078` (floors,
  budget, backoff, deterministic wrappers), `:6090-6210` (view-change
  gate incl. grace), `:5955-6018` (fast-forward).
- Validity: `stellereum/src/runtime.rs:4860-5135`
  (unaligned checks incl. timestamp/shard/root/commitments/evidence),
  `:4612-4653` (timestamp), `:2674` (is_proposer), `:3441-3917`
  (propose incl. locked/demanded/fresh), `:2902-2942` (prebuild).
- Packing caps: `stellereum/src/mempool.rs:740-745`, `:2371-2521`;
  `stellereum/src/runtime.rs:27,51,75,2719`.
- Numbers: `docs/PROPOSER_REWORK.md` §§1–5 (ground truth, rejected (b)
  proof, recommended (c), sim table); `docs/TEMPO_PROFILE.md` §§2–5
  (loopback phases, WAN/LAN sims, VEL BEFORE/AFTER, ranked levers).
- Absent: `docs/BFT_COMPARISON.md` (not present — not cited).
