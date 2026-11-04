# CONSENSUS HOTPATH — definitive map (propose → prevote → polka → precommit → QC → finalize → apply)

> Scope: read-only map of the consensus critical path in this repo. No live ops, no code changes.
> Companion docs `docs/PROPOSER_REWORK.md` and `docs/TEMPO_PROFILE.md` are **absent** from `docs/` at time of writing (checked 2026-11-01) — this file does not duplicate them; where the code cites them (§2c straggler grace, §5.3 timer accounting) the relevant formulas are restated inline with code pins.
> All `file:line` pins below were read from the working tree. Timings taken verbatim from code/constants/comments are plain; anything inferred is marked **ESTIMATE**.

## 0. Constants cheat-sheet (all code-stated)

| Knob | Value | Pin |
|---|---|---|
| Tick quantum `TICK_MS` / batch window `BATCH_MS` | 50ms / 50ms | `src/main.rs:1236,1243` |
| Round-timeout base (`STELL_ROUND_TIMEOUT_MS`) | default 3000ms, clamp 200ms–3,600,000ms | `src/main.rs:3644-3654` |
| Deterministic backoff | +500ms/round, cap +10,000ms | `src/consensus.rs:3834,3840` |
| Adaptive (slow-proposer) extension | +500ms/ledger-miss, cap +5,000ms | `src/consensus.rs:3841-3853` |
| DOWN-PROPOSER fast cap (`STELL_DOWN_PROPOSER_TIMEOUT_MS`) | 800ms | `src/main.rs:139,142` |
| Round-0 cap (`STELL_ROUND_ZERO_TIMEOUT_MS`) | 650ms | `src/main.rs:151` |
| Nil-prevote wait | `2 × base round_timeout` (+ optional straggler grace) | `src/main.rs:4660-4664` |
| Peer-active hold bound (`hold_bounded`) | fires at `max(effective, 2 × base)` while peer active | `src/main.rs:6099-6100,6211` |
| Straggler grace (`STELL_STRAGGLER_GRACE_MS` / `_CAP_MS` / `_FRESHNESS_MS`) | default 0 / 30,000 / `5 × base` | `src/main.rs:178-203` |
| Retransmit cadence | `max(150ms, timeout/2)`, doubling per elapsed timeout, cap `2 × timeout` | `src/consensus_net.rs:221-227` |
| Vote send dedup TTL | 200ms | `src/consensus_net.rs:150` |
| Inbound drain caps | 512 envelopes/tick, inner `512×4=2048` verified/tick, Committed proofs 8/tick, deferred 1024, batch 32 msgs, pending chunks 256 | `src/main.rs:1248-1252,4702`, `src/consensus_net.rs:81,137,3861` |
| Superseded-vote lag | 2 rounds | `src/consensus_net.rs:158` |
| Quorum | `floor(2·total/3)+1` power; empty set → `u64::MAX` (never quorums) | `src/consensus.rs:1387-1406` |
| Scan windows | `ROUND_LOOKBACK=8`, `MAX_SCAN_SPAN=4096`, `REPHASE_SCAN_WINDOW=4096`, `MAX_RETAINED_VOTE_ROUNDS=4096` | `src/consensus.rs:181,3770-3809` |
| Sync/jump guards | `+8` rounds/call (`sync_round_to`), 8 jumps/round, `+1`/msg (`advance_to_round`), accept window `MAX_ROUND_AHEAD=1000` | `src/consensus.rs:150,167,3755,4529,4760` |
| Deadlock breaker | 300s no-progress (`STELL_DEADLOCK_TIMEOUT_SECS`), jump ≤65536 rounds, corroborated (≥2 peers, 1 if set<3) | `src/consensus.rs:3770,4858-4919` |
| Nil-storm breaker | K=3 consecutive nil rounds, one-shot widen + rebroadcast | `src/consensus.rs:3826,4678,4715` |
| Downtime ledger threshold | `DOWNTIME_MISS_THRESHOLD=10` | `src/staking.rs:238` |
| Min-block floor | 50ms (`STELL_MIN_BLOCK_MS`, 0 disables) | `src/main.rs:980` |
| Catch-up probe | 2000ms | `src/main.rs:43` |
| Measured (comments, not constants) | r0 proposal→precommit-QC ~160–580ms; bumper-to-bumper ~0.5–1s; apply ~16ms/428-tx (≈19ms/500tx); loaded validation ~164ms/proposal (~36ms fast path); packing ~41ms cold/~11ms warm; 1-vCPU responder p50 ~660ms; 26.7% wasted rounds = lost messages; 1177s outlier at #307819 (skew/lock-split) | `src/main.rs:993-1024,5970-5973,6411-6417` |

---

## 1. PROPOSE — entry points

**Canonical entry:** `src/runtime.rs:3441` `ValidatorRuntime::propose(timestamp)`.
**Loop call sites:** top-of-tick gate `src/main.rs:4472-4565`; same-tick fast-forward after finalize `src/main.rs:5990-6017` (requires `has_prebuild_for`, `src/runtime.rs:2873`).

**What triggers it:** all of `can_vote && !has_pending_apply() && is_proposer() && !has_live_proposal() && min_block_time elapsed` (`src/main.rs:4472-4476`; `can_vote` = `effective_can_vote`, `src/runtime.rs:6946`; `is_proposer`, `src/runtime.rs:2674`). Locked proposer re-proposes its locked body verbatim (`src/runtime.rs:3481-3509`); else lock-hint rescue (`src/runtime.rs:3511+`), else fresh build. Success → `ConsensusMsg::Proposal` enqueued (`src/main.rs:4545-4556`), large bodies force-flush (`src/main.rs:4552-4555`; `is_large`, flush `src/main.rs:1393`).

**What can delay it (with costs):**
- `has_pending_apply()` — sequenced worker still executing H; propose returns `None` (`src/runtime.rs:3454`). Cost: full apply latency (~16–19ms typical per §0; ESTIMATE larger for fat shielded blocks) — but loop keeps draining (`src/main.rs:5351-5370`).
- `min_block_time` 50ms floor (`src/main.rs:980,4476`) — deliberate pacing, ESTIMATE ~0–50ms.
- Fresh-build packing ~41ms cold / ~11ms warm (comment-measured, `src/main.rs:1003-1007`); VEL-1 `prebuild_next_proposal` (`src/main.rs:4469-4471`, `src/runtime.rs:2902`) moves it to the idle window; fast-forward saves one 50ms tick/height (`src/main.rs:5966-5989`).
- `on_proposal` receive path (`src/runtime.rs:5599`): deferred while apply in flight (`src/runtime.rs:5611`); proposer-sig verify first, then root/header checks. `HeightConsensus::receive_proposal` (`src/consensus.rs:3971`) refuses unless `step==Propose` + correct scheduled proposer + one value/round (equivocation-safe idempotent re-receipt).
- Proposal loss on best-effort pubsub → peer never votes → whole round lost (re-send on timeout `src/main.rs:6235-6253`, thin-block periodic re-send `src/main.rs:6449-6464`).

## 2. PREVOTE (own vote + nil fallback)

**Entries:** `make_prevote` `src/runtime.rs:5842` (step gate Propose/Prevote + `decide_prevote` `src/consensus.rs:4008` = proposal if unlocked, locked value if match, else nil); cast once/round (`last_prevoted`, `src/main.rs:4576-4594`); self-admit via `on_prevote` (`src/runtime.rs:5850`) → `hc.add_prevote` (`src/consensus.rs:4028`); enqueue with `lock_hint` (`src/main.rs:1224`, enqueued `src/main.rs:4581-4587`, immediate flush).

**Nil path:** `src/main.rs:4595-4688`. Fires only if `!has_live_proposal && elapsed ≥ 2×base (+nil_grace) && !peer_alive_in_round` (`src/main.rs:4660-4664`; `peer_alive_in_round` = peer at our height within ±1 round heard inside `round_timeout`, `src/main.rs:4628-4634`). Nil vote is value-less (`block_hash=None`, debug-asserted `src/main.rs:6667-6670`), carries lock hint for rescue, decides nothing.

**What can delay it:** 2×base wait is the dominant cost (e.g. 6s at 3s base; 1.6s at live 800ms) — deliberate anti-nil-storm hold; `peer_alive_in_round` extends it while a peer talks (liveness over speed). Straggler `nil_grace` adds `straggler_hold_ms` (`src/main.rs:219-244`) when enabled (default 0 → byte-identical).

## 3. VOTES DRAIN / FAN-IN / VERIFY (the fan-in choke point)

**Entry:** `'drain` loop `src/main.rs:4690-4709`: up to `MAX_INBOUND_PER_TICK=512` envelopes (`src/main.rs:1248`), inner budget `INNER_BUDGET_PER_TICK=2048` flattened verifies (`src/main.rs:4702`); past budget → flood tail dropped loudly, Committed still admitted (`src/main.rs:4838-4849`); deferred bulk capped at 1024, live-first (`src/main.rs:1249-1252,4703-4706`); Committed proofs 8/tick (`src/consensus_net.rs:3861`); batches ≤32 msgs (`src/consensus_net.rs:81`).

**Per-vote path:** authenticate FIRST (`Vote::verify` + membership inside `on_prevote`/`on_precommit`, `src/main.rs:4997-5024`), admit to `VoteSet::add` (`src/consensus.rs:2330`, scope+sig+member+first-vote-wins, equivocation recorded once), feed `peer_rounds` counter for verified same-height votes (`src/runtime.rs:5850-5884`, `5950-5965`), future-rule chase via `observe_peer_round`→`sync_round_to` (`src/consensus.rs:4780-4799,4516`, +8/call, corroboration ≥2 beyond lookback).

**What can delay it:** signature-verification CPU under flood (the caps exist so a max-size batch flood can't stretch verify past the round timeout, `src/main.rs:4690-4699`); per-tick caps defer (never drop, except inner-budget tail) → ESTIMATE adds ≤1–N ticks (50ms each) of vote latency under burst; refused votes still stamp `peer_round_seen`/RX clocks (liveness bookkeeping, `src/main.rs:3719-3724`).

## 4. POLKA (prevote QC) → PRECOMMIT (own vote)

**Polka detection:** quorum = `VoteSet::quorum_target` (`src/consensus.rs:2477`, power ≥ `quorum_power`). Two redundant mechanisms (deliberate): **ledger** `note_polka` on every admitted prevote (`src/consensus.rs:4377`, called `src/consensus.rs:4058`, newest-wins, nil never a polka) and **scan** `try_polka_at` over `rounds_to_inspect` (`src/consensus.rs:4344`, newest-first, window `scan_floor` `src/consensus.rs:4171` = `min(our_round, max_peer_round) − lookback`, floored at `our_round − 4096`). `best_polka` = newer of the two (`src/consensus.rs:4409`).

**Own precommit:** `make_precommit` `src/runtime.rs:5898` — runs `try_prevote_quorum_at` (unlock side-effect, `src/consensus.rs:4246`) then follows newest **polka** (never newest-quorum-of-any-kind; nil-shadowing fix `src/runtime.rs:5909-5928`), requires matching `prevote_qc`, enforces lock (`locked_block != target && qc_round <= locked_round` → refuse, `src/runtime.rs:5939-5943`), locks at polka round, stamps vote **at the polka's round** (skew fix, `src/runtime.rs:5947`), dedup key `(height, v.round)` (`src/main.rs:5313-5334`), immediate flush + lock persistence (`src/main.rs:5335-5346`).

**What can delay it:** round skew (precommit waits for the polka's own round to be visible — ledger covers late polkas, scan covers joined-late nodes); lock refusal (correct — safety); missing `prevote_qc` entry (cert build needs sortition parent, `src/consensus.rs:4352-4356`).

## 5. PRECOMMIT QC → DECIDE (lock + QC)

**Entry:** `HeightConsensus::try_precommit_quorum` `src/consensus.rs:4436`. Candidates = scan window **plus** observed-polka round (late-polka fix, `src/consensus.rs:4437-4442`); requires precommit QC **and** same-round prevote QC for the **same** block (`src/consensus.rs:4454-4466`); refuses against own lock (`src/consensus.rs:4470-4474`); builds/stores `precommit_qc`, advances lock monotonically (never regresses, `src/consensus.rs:4486-4488`), sets `decided` + `step=Commit` (`src/consensus.rs:4489-4490`), clears nil streak.

**What can delay it:** precommit leg lost in transit (measured 31/180 wasted rounds live, `src/runtime.rs:5898-5904` — fixed by polka-round stamping + retransmit); bodyless-but-QC state (decide exists but finalize waits for body — correct fork guard); lock-split (needs higher-round counter-polka to unlock, `src/consensus.rs:4312-4318`).

## 6. FINALIZE → APPLY (sequenced worker)

**Entries:** `prepare_decided_block` `src/runtime.rs:6386` (single-flight gate, `try_precommit_quorum`, body-present + hash re-check, order-commitment, actor-cap, QC attach + stash `last_decision`, in-force-set power re-check — refuses weak/unilateral finalize `src/runtime.rs:6500-6538`); `try_finalize_submit` `src/runtime.rs:6597` (queue `LaneJob::Apply`, return hash now); `try_poll_apply` `src/runtime.rs:6628` (install outcome, advance height, fresh `HeightConsensus(height+1)` + `set_parent_hash`, `src/runtime.rs:6575-6581` / `src/runtime.rs:6921-6928` for `apply_and_advance`).

**Loop wiring:** submit `src/main.rs:5363-5369` → poll `src/main.rs:5370-5402` → publish head/body/header on `publish_lane` (`src/main.rs:5413-5456`), `Committed` broadcast with stashed proof (`src/main.rs:5464-5478`), fast-forward propose (`src/main.rs:5990-6017`). Blocked-finalize diagnostics via `finalize_blockers` (`src/consensus.rs:4185`, logged `src/main.rs:6019-6029`).

**What can delay it:** apply execution (~16–19ms typical, §0) — off-tick so it never blocks the drain; missing body / order-mismatch / actor-over-cap / weak QC → hard refusal (chain-safe stall, loud logs); `has_pending_apply` gates propose + proposal validation + next submit (backpressure, not deadlock).

## 7. TIMEOUTS — deterministic ladder, caps, holds, grace, breaker

**Core value (same on all honest nodes):** `deterministic_round_timeout_ms(base, round, missed_streak) = base + min(round×500, 10000) + min(missed×500, 5000)` (`src/consensus.rs:3891-3903`), wrapped `src/main.rs:1064`. Legacy local-counter variant `effective_round_timeout_ms` (`src/main.rs:1043`) kept for compat/tests only.

**Per-round effective deadline** (`src/main.rs:6156-6164`): `backoff_ms`, then `min(backoff, 800ms)` if DOWN-PROPOSER (ledger `missed ≥ 10`, deterministic, skipped with live proposal — `src/main.rs:6123-6136`, predicate `src/main.rs:1076`), else `min(backoff, 650ms)` if round-0 without live proposal (`src/main.rs:6158-6161`), else `backoff_ms`.

**Execution holds (never part of the value):**
- `hold_bounded` (`src/main.rs:6099-6100`): while `peer_is_active_nearby` (same height, ±1 round, heard < 2×base, `src/main.rs:6067-6079`) or `peer_alive_recently` (same height, heard < base, `src/main.rs:6095-6098`), and `elapsed < 2×base` → view-change deferred; gate fires at `max(effective, 2×base)` (`src/main.rs:6211`; accounting proof `src/main.rs:10603-10653`, measured 19–21s rungs at 10s base).
- Straggler grace (`src/main.rs:6173-6210`): `straggler_hold_ms` (`src/main.rs:219-244`, clauses: behind-vote / unheard-proposal, freshness `5×base`, never for ahead peers), capped to `2×base − effective` slack (`cap_hold_to_two_x_bound`, `src/main.rs:260-262`), metric `straggler_grace_extends` (`src/metrics.rs:968`).
- Nil-vote wait (§2) spends the vote but never gates the view change (`src/main.rs:6194-6203`).

**On fire** (`src/main.rs:6211-6274`): re-enqueue own votes (fresh `lock_hint`) + own proposal, flush-if-new (storm fix, `src/main.rs:6254-6264`), `next_round()` (`src/consensus.rs:4619`: classifies nil, charges proposer-miss, saturates round, `timeouts+=1`, refills jump budget, clears proposal state), reset round timers/vote guards, one-shot nil-breaker (`src/main.rs:6283-6324` → `apply_nil_convergence` `src/consensus.rs:4715`: widen scan to 4096 once/streak + rebroadcast QC-backed body).

**Deadlock breaker** (`src/runtime.rs:5564` + `src/main.rs:6345-6409`): after 300s without finalize, corroborated jump (≤65536, forward-only, ≤1/timeout window); complement local re-phase when nobody is ahead (`deadlock_local_reset_due` `src/consensus.rs:4951` → `apply_deadlock_local_reset` `src/consensus.rs:5042`: +1 round, widen scan, drop only bodyless+QC-less lock).

## 8. RETRANSMIT / FAN-OUT

- Periodic: every `retransmit_interval_ms(base, elapsed)` (`src/consensus_net.rs:221`, `src/main.rs:6424-6428`) re-enqueue own votes + thin (≤32-tx) proposals if not already queued (`src/main.rs:6429-6470`); idempotent via outbox dedup (`enqueue_outbox` `src/main.rs:1276`, vote key `(h,r,kind,voter)` + lock-hint upgrade, Committed height-dedup) and receiver `VoteSet` (first-vote-wins).
- Batching: 50ms window → one `Batch` (≤32 msgs) per flush (`src/main.rs:6472-6477`, `src/consensus_net.rs:81`); large proposals bypass (`src/main.rs:4552-4555`); send-side vote dedup 200ms TTL (`VoteSendFilter`, `src/consensus_net.rs:232-259`) collapses same-tick triple-enqueue (retransmit/view-change/flush) without touching loss recovery; superseded (≥2 rounds old) votes/proposals dropped at send (`coalesce_for_send` `src/consensus_net.rs:199`, `is_superseded_proposal` `src/main.rs:1342`); backpressure at 256 pending chunks (`src/consensus_net.rs:137`).
- Measured need: 26.7% of wasted rounds were pure loss (18.8% proposals), 31 rounds had full prevote QC but lost precommit leg (`src/main.rs:6411-6417`, `src/runtime.rs:5898-5904`).

## 9. LOCK RULES × HOTPATH (interaction table)

| Rule | Pin | Hotpath effect |
|---|---|---|
| Prevote follows lock (`decide_prevote`) | `src/consensus.rs:4008-4020` | Locked node prevotes locked value or nil; fresh proposals from others get nil from locked nodes → both sides stall without unlock path |
| Unlock on newer counter-polka only (`polka_round > locked_round`, non-nil, newest-wins) | `src/consensus.rs:4306-4318` | Only path that releases a lock without finalizing; older conflicting quorums can't unlock past newer confirming ones; nil never unlocks (safety) |
| Precommit refuses counter-lock (`qc_round ≤ locked_round` + different value) | `src/runtime.rs:5939-5943` | Stale polkas can't pull a vote; node waits for a polka above its lock |
| Decide refuses counter-lock; lock monotonic | `src/consensus.rs:4468-4488` | Late same-value quorums can't regress the lock; conflicting values never decide locally |
| Locked proposer re-proposes locked body | `src/runtime.rs:3481-3509,3457-3466` | Convergence path: network votes the locked value, QC forms, finalize |
| Nil votes carry lock hint; rescue re-proposal | `src/main.rs:1224`, `src/runtime.rs:3511+` | Bodyless-locked peers advertise; scheduled proposer re-serves the demanded body verbatim |
| Re-phase drops only bodyless + QC-less locks | `src/consensus.rs:5042-5054` | QC-backed locks survive deafness (stall over fork, explicit trade `src/consensus.rs:5025-5034`) |
| Restart persists lock (`ConsensusCheckpoint`) | `src/main.rs:5335-5346` | No double-vote / re-vote across restarts |

---

## 10. RANKED IMPROVEMENTS (speed/safety; no code changed here)

1. **Shrink the peer-active hold bound from `2×base` toward `~1.25–1.5×base` (or make it evidence-graded).** Pin `src/main.rs:6099-6100,6204-6211` (+ proof `src/main.rs:10603-10653`). Expected effect: every peer-active rung drops from ~2×base to ~1.3×base (e.g. at 3s base, ~7s→~4s per wasted round; at 10s TEMPO base, ~20s→~13s). Risk: MEDIUM — the 2× window is the leapfrog fix (`src/main.rs:6045-6050`); narrowing re-opens lockstep advance on lossy WAN. Gate on live re-measurement + keep `peer_alive_recently` path intact.
2. **Verify-then-admit inbound batches in parallel (bounded worker pool) instead of serial per-tick verify.** Pins `src/main.rs:4690-4709`, `src/consensus.rs:2330-2345`. Expected effect: removes the verify-CPU term (~164ms loaded per proposal, `src/main.rs:1003-1007`) from the tick critical path; raises effective inner budget without raising stall risk. Risk: MEDIUM — signature-batch ordering + equivocation dedup must stay deterministic; CPU contention with apply worker needs a cap.
3. **Cut happy-path vote latency: flush own prevote/precommit immediately (already done) and extend immediate-flush to the polka-triggered precommit + Committed (already done) — next step is shrinking `BATCH_MS` 50ms→10–20ms for non-vote traffic only.** Pins `src/main.rs:1236,6472-6477`. Expected effect: ESTIMATE ~30–40ms saved per height on the residual batched path; votes already bypass. Risk: LOW — more `request_to` round trips per peer; keep large-message immediate flush and measure weak-member CPU first.
4. **Replace the fixed `2×base` nil-prevote wait with `min(2×base, effective + small_margin)` when the deterministic deadline already exceeds base.** Pin `src/main.rs:4660-4664`. Expected effect: at high rounds/backoff the nil vote (which unblocks peers' behind-trackers and retro help) fires earlier; ESTIMATE saves up to one backoff increment per slow round. Risk: LOW-MEDIUM — earlier nils raise nil-quorum share; nils decide nothing, but they can shadow value votes toward a nil QC in marginal power splits.
5. **Promote the round-0 650ms cap to a proposer-aware deadline (skip the cap when the scheduled proposer has a fresh-miss streak > 0).** Pins `src/main.rs:6158-6161`, streak source `src/main.rs:6110-6120`. Expected effect: removes a needless view change when a historically-slow proposer was always going to need ~1s; ESTIMATE converts some r0 timeouts into value votes. Risk: LOW — deterministic inputs only (ledger streak), so no divergence; keep the absolute cap as ceiling.
6. **Add a body-request fast path on `quorum-reached-but-bodyless` (pull the decided hash immediately instead of waiting for retro/retry).** Pins `src/runtime.rs:6407-6413`, retro cursor `src/main.rs:5419-5424`. Expected effect: cuts the bodyless-QC stall (the 3-day #285027 shape) from retro-window timescales to ~1 RTT. Risk: MEDIUM — new request path = new DoS surface; bound concurrency, verify QC before fetching, never finalize without the hash re-check (`src/runtime.rs:6421-6427`).
7. **Raise `INNER_BUDGET_PER_TICK` selectively for verified-member votes (or split the budget: member votes vs. everything else).** Pins `src/main.rs:4700-4702`. Expected effect: honest bursts (catch-up fan-in after partition) clear in fewer ticks; flood tail still capped. Risk: LOW-MEDIUM — attacker can still mint member-spoofed envelopes, but signature verify fails fast; verify cost of failures must be measured so the split doesn't become the bypass.
