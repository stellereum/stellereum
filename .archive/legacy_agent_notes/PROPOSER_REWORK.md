# Proposer rework: breaking the unanimity stale-chase

Status: DESIGN + SIM-ONLY PROOF. No production code changed, no live ops.
Scope lock: design doc + simulator harness/test extensions only
(`stellereum/tests/support/consensus_cluster.rs`,
`stellereum/tests/sim_proposer_straggler.rs`, this file).
Production consensus (`stellereum/src/consensus.rs`,
`stellereum/src/runtime.rs`, `stellereum/src/main.rs`) is untouched.

## 1. Ground truth (observed live, 15 hours)

- 3 validators, unanimity quorum 3/3 (total power 3, quorum 3 — ANY split
  stalls). One member (B) on a 250ms+ link, one (D) on 1-vCPU slow ticks, one
  (A) beefy datacenter. Round timeout base 20000ms (3.5s base provably stalls;
  pinned by `stellereum/tests/unanimity3_slow_voter_tests.rs`).
- Steady-state failure: all three aligned (same height, same round, same
  validator set, same binary, same epoch family), proposals and votes flowing
  in ALL directions (RX-logged on every node), votes verifying (`add_ok`), yet
  QCs form ~1 per 5 minutes. Rounds advance on timeouts (~20s effective);
  votes constantly arrive "one round stale" and are silently absorbed into old
  buckets; everyone self-proposes in own slots; nil-votes interleave on dead
  slots. No single component is broken — the COMBINATION under unanimity never
  converges: whoever is 1 round behind votes stale forever (their vote never
  counts), and the leader pair (any 2/3 < quorum) cannot decide alone.
- Existing stabilizers (all read, none changed): future-round rule +
  `sync_round_to` (`ROUND_LOOKBACK=8`, `MAX_SYNC_JUMPS_PER_ROUND=8`,
  corroboration gate, per-second budget) in `note_peer_vote_round`
  (`stellereum/src/runtime.rs:5331`); `peer_alive` nil-withhold;
  DOWN-PROPOSER fast timeout; deadlock breaker (318s);
  `deterministic_round_timeout_ms` per-round backoff ladder
  (`stellereum/src/consensus.rs:3508`); VEL-1 prebuild + vote-fan-in.

## 2. Candidate directions (each modeled, exactly one recommended)

### (a) Scheduled-proposer stickiness

MECHANISM: while a node holds no live proposal, do not nil-vote or
view-change past a bounded grace when the scheduled proposer of
(height, round) may still deliver — i.e. gate the nil wait and the round
timeout on the schedule instead of racing them. Production touch points would
be the nil path (`HeightConsensus::decide_prevote`,
`stellereum/src/consensus.rs:3625`, plus the production loop's "prevote NIL
after twice the round timeout without one") and the view-change timer
(`deterministic_timeout_for`, `stellereum/src/main.rs:960`), keyed on
`proposer_for` (`stellereum/src/consensus.rs:1284`) and
`has_live_proposal` (`stellereum/src/consensus.rs:3619`).

SAFETY: timing-only. No vote content, validity, bucketing
(`VoteSet::quorum_target`, `stellereum/src/consensus.rs:2285`), quorum
arithmetic (`quorum_power`, `stellereum/src/consensus.rs:1197`), lock rules
(`decide_prevote` lock check; `try_precommit_quorum` same-round
prevote+precommit agreement + lock refusal,
`stellereum/src/consensus.rs:4041-4095`), or QC verification
(`qc_meets_quorum`, `stellereum/src/consensus.rs:1246`) changes. Quorum
intersection is untouched: quorums still form per (height, round) under one
validator set.

LIVENESS (partial): fixes slow-PROPOSER rounds — the fast pair waits for the
slow proposal instead of nil-ing and racing ahead, so the unanimous value QC
can form. Does NOT fix fast-proposer rounds: there the proposal is already
held and it is the straggler's VOTE that is late; waiting on the proposal
buys nothing.

RISKS: waiting on a scheduled proposer that is actually DOWN stretches every
one of its rounds by the grace (bounded, but pure loss) — needs the
DOWN-PROPOSER fast timeout as backstop; covers only ~1/3 of stalls (proposer
slots), leaving the voter-lag chase intact.

VERDICT: reject standalone. Its correct half (proposal-wait) is folded into
the recommendation as clause (2); alone it cannot break the cycle because
most stalled rounds already have a live proposal — they are missing the third
VOTE.

### (b) Vote-forwarding / retention (count late votes toward the current QC)

MECHANISM (as proposed): a vote for (height, r) naming value V also counts
toward the (height, r+1) prevote QC when r+1 proposes the same V — "the vote
was for the right value, just an old round".

SAFETY: UNSAFE — rejected with proof. (i) It mixes rounds: two quorums
(r for A, r+1 for B≠A, the latter built partly from carried r-votes) could
both reach quorum power from overlapping-but-distinct voter sets, defeating
the same-round prevote+precommit agreement gate in `try_precommit_quorum`
(`stellereum/src/consensus.rs:4065-4071`) and deciding two values at one
height — a fork. (ii) It breaks the lock invariant: `decide_prevote`
(`stellereum/src/consensus.rs:3623-3637`) plus the lock
(`locked: Option<(BlockHash, Round)>`, `stellereum/src/consensus.rs:3248`)
assume one vote per (height, round, kind); carried votes let one validator's
power certify two rounds, violating "a locked validator must not decide a
block that contradicts its own lock" (pinned by test at
`stellereum/src/consensus.rs:5592`). (iii) The codebase already considered
and rejected exactly this: "Counting r-prevotes toward an r+1 QC would
additionally MIX rounds: two different quorums (r for A, r+1 for B) could both
'decide' and break quorum intersection. Safety over grace."
(`stellereum/src/consensus.rs:3491-3493`, the (1b) rejection).

LIVENESS: would "work" by definition (stale votes stop being stale) — that is
precisely why it is unsafe: it redefines away the protection.

VERDICT: reject, unanimously. No sim built — an unsafe mechanism needs no
benchmark.

### (c) Adaptive straggler-aware round extension — RECOMMENDED

MECHANISM: slow the round rate while a straggler is detected via observed
peer rounds, instead of racing a fixed backoff. Two evidence-gated clauses,
each bounded by a per-round cap and each requiring FRESH evidence (a silent
peer stops stretching rounds once its last observed vote ages out, so a dead
peer cannot park the chain — only a live-but-slow one buys extra time):

- Clause (1) BEHIND-VOTE: some live validator was recently observed voting
  at an older (height, round) than ours — its vote for our round may still be
  in flight, so hold the round open one grace before view-changing.
- Clause (2) SCHEDULED-PROPOSAL (the sound half of (a)): we hold no live
  proposal and the scheduled proposer of our (height, round) is not
  demonstrably ahead of us — its proposal may still be in flight, so wait for
  the scheduled value instead of racing to the next round proposalless.

The same grace stretches the nil-vote wait (don't nil a round whose scheduled
value may still be in flight — the vote equivalent of clause (2)); value
votes are unaffected (they fire immediately on a live proposal).

Signal path (all existing production machinery, read-only): per-peer rounds
are already recorded from verified votes (`note_peer_round`,
`stellereum/src/consensus.rs:4416`; `observe_peer_vote`,
`stellereum/src/runtime.rs:5432`; `supporting_peers_count`,
`stellereum/src/consensus.rs:4424`; `max_peer_round`,
`stellereum/src/consensus.rs:4450`). Actuator (production mapping, NOT
implemented here): a bounded additive term OUTSIDE the deterministic core —
`deterministic_timeout_for` (`stellereum/src/main.rs:960`) and
`deterministic_round_timeout_ms` (`stellereum/src/consensus.rs:3508`) stay
byte-identical (same-on-all-nodes); the wrapper adds
`min(grace, cap)` iff fresh straggler evidence exists, plus the same grace on
the nil wait. Env-gated, default 0 = current behavior.

SAFETY: timing-only, same case as (a), strictly stronger: vote content,
validity, per-(height, round, kind) bucketing, quorum arithmetic, lock rules,
QC verification, one-vote-per-(height, round, kind) (no new equivocation),
and the proposer schedule are all untouched. Quorum intersection holds: any
two QCs are still same-round, same-height, same-set, intersecting in ≥ quorum
power (under 3/3: identical membership). Heterogeneous timeouts cannot fork:
Tendermint safety is time-free; only liveness uses timing, and the grace only
ever WIDENS honest-round overlap.

On the `main.rs` determinism invariant: `deterministic_timeout_for`
(doc at `stellereum/src/main.rs:944-961`) deliberately removed local
observation from timeout VALUES after the `vote_seen_from_proposer`
divergence bug. The recommendation respects the letter (the deterministic
core is untouched) and narrows the exception: a bounded, additive,
self-expiring execution hold, never a base value — the same category as the
already-accepted "local holds (peer-active wait, retransmit)". Precedent that
heterogeneity is already real: 1-vCPU slow ticks make EFFECTIVE round rates
heterogeneous today; the grace makes the fast nodes' heterogeneity converge
the network instead of outrunning it. The sim (§4) is the evidence that
clocks converge rather than diverge under it.

LIVENESS: under unanimity the binding constraint is assembling all 3 votes in
one round; the fast pair racing at base rate outruns the slowest honest
member's vote/proposal latency. Extending the round while a behind-but-live
member (clause 1) or an unheard scheduled proposal (clause 2) is detected
makes the round cover the slowest honest latency, so all votes land
in-bucket, the polka forms at the current round, precommits follow at the
polka's round, QC → finalize. Breaks BOTH halves of the observed cycle
(slow-proposer rounds via clause 2, fast-proposer rounds via clause 1),
which is why it succeeds where (a)-pure cannot. Dead peers age out of the
freshness window → normal timeouts (unanimity + truly-down member still
halts, as quorum arithmetic demands — cf.
`stellereum/tests/sim_dead_member_4node.rs`). Per-round cost is capped; the
deadline is fixed per round (fresh votes do not push it further), so no
indefinite stretch exists even under a live-but-slow Byzantine.

RISKS: (i) a Byzantine that votes just slowly enough to stay "fresh" stretches
every round to base+cap — bounded DoS of the same class as the existing
adaptive cap (`ADAPTIVE_EXTENSION_CAP_MS`), tunable via cap/freshness;
(ii) transient phase-skew widening while grace is active (healed by the
unchanged future-rule jumps — measured: fast-pair jumps stay ~hundreds over
thousands of heights); (iii) the nil-wait stretch delays nil-visibility of a
genuinely proposalless round by up to the cap (bounded; DOWN-PROPOSER fast
path unaffected).

### (d) Straggler-triggered re-serve (own idea — evaluated, not recommended)

MECHANISM: when behind-evidence fires, the scheduled proposer immediately
re-broadcasts its proposal and members re-broadcast their current-round votes
(without waiting for the view-change resend that production and the harness
already perform in `step_round_timeout`).

SAFETY: delivery-only; counting rules untouched — safe.

LIVENESS: insufficient alone. The chase is a RATE problem (rounds close
before the slow vote arrives), not a DELIVERY problem (the votes/proposals
already arrive — just late; production already resends on view change).
Re-serving earlier does not lengthen the round the vote must land in.

VERDICT: reject standalone. Complementary at most — and already largely
present as the view-change retransmit. The sim's residual waste (§4) traces
to exactly this resend path, confirming it moves votes without deciding
rounds.

## 3. Recommendation

Implement (c): bounded, freshness-gated, straggler-aware round extension
(clauses 1+2) plus the same grace on the nil wait — behind a default-off env
flag, as an additive term outside the deterministic timeout core.

(a) is subsumed (its sound half is clause 2; its pure form covers only
proposer-slots). (b) is unsafe (proof above — no benchmark needed). (d) is
harmless but rate-blind.

## 4. Sim proof (same seed, with/without — NOT on live)

Harness: `stellereum/tests/support/consensus_cluster.rs` extended MINIMALLY
and SIM-ONLY (new `StragglerPolicy`, default disabled; per-peer vote
sightings; stale-arrival + waste + `grace_extends` + `view_changes`
counters; grace applied to view-change and nil-wait only when the policy is
enabled — control behavior bit-identical). Scenario:
`stellereum/tests/sim_proposer_straggler.rs`, seed `0xC10C_0007`, tick 100ms,
base 100ms (tight: the compressed analogue of the live 3.5s base that the
slow link outruns), slow member 5x timeout factor with the live-exact 250ms
inbound + propose delays, budget 1_200_000 virtual ms (20 virtual minutes) per
test, grace 1500ms / cap 1500ms / freshness 3000ms.

Repro:

```text
cargo test --test sim_proposer_straggler -- --nocapture
cargo clippy -p stellereum --all-targets -- -D warnings   # 0 warnings, 0 errors
```

Measured (paste of the `[sim]` lines, seed `0xc10c0007`):

| metric (20 virtual min) | control (policy off) | fixed (policy on) |
|---|---|---|
| finals best/common | 0 / 0 (0 per virtual hour) | 1787 / 1787 (5,361 per virtual hour) |
| stale-arrival share (nodes 0/1/2) | 1.000 / 1.000 / 0.000 | 0.522 / 0.524 / 0.562 |
| wasted-vote share (buckets that never decide) | 1.000 / 1.000 / 1.000 | 0.063 / 0.062 / 0.063 |
| view changes (nodes 0/1/2; total) | 12000 / 12000 / 759 (24,759; ∞ per final) | 1790 / 1791 / 1788 (5,369; ≈3.0 per final) |
| rounds burned | 12000 / 12000 / 11994 at h=1 | ~1 round per height (all decide deltas 0 post-transient) |
| slow-member sync jumps | 5,969 (chase, zero convergence) | 1 (no chase) |
| grace engaged (ticks) | 0 (policy off) | 8254 / 8226 / 27 |
| nil prevotes | 0 everywhere (round churn outruns the nil gate at tight base) | 0 everywhere |
| safety | vacuous (no fork, no double-votes) | no fork, no double-votes, state roots agree |

Reading the table:

- STALL-RATE COLLAPSE: 0 → 1,787 finals in the same window, same seed, the
  only difference being the policy flag. Decide deltas are 0 for every
  post-transient height (first height delta 3 is the virtual t=0 genesis
  transient, also present in `sim_happy3`).
- WASTE (the load-bearing half of "stale"): 1.000 → ~0.063, ~16x reduction.
  Control: every arrival sits in a bucket that never decides.
- STALE ARRIVALS (the incident's surface signature): 1.000 → ~0.53. The
  residual is understood, not hand-waved: the slow member's 500ms timeout
  still fires mid-height (it cannot extend — it is the laggard, everyone else
  is with or ahead of it), and its production-faithful view-change resend
  carries its proposal stamped with the new round; when it happens to be
  scheduled for that round too, peers accept it and cast votes in a bucket
  that never reaches QC — while the round-0 QC still decides first (deltas
  prove it). Late-but-counted vs never-counted is exactly why the doc reports
  waste alongside staleness.
- ROUNDS USED: 12,000 burned at height 1 → ~1 view change per finalized
  height (≈3.0 per final across the cluster, dominated by the laggard's
  unavoidable mid-height timeout).
- MECHANISM PINNED, not just outcome: `grace_extends` 8254/8226 on the fast
  pair (the fix ran), slow-member jumps 5969 → 1 (the chase stopped).

Harness limits (per `docs/SIMULATOR.md` §4, honestly): flat per-node timeout
(not the production backoff ladder — a stuck height spins FASTER here, so the
stall verdict arrives sooner); no partitions/asymmetric links (delay is
per-receiving-node + per-sender propose delay — sufficient for the
slow-member shape, insufficient for split-brain); no restart-mid-run; nil
interleaving and lock divergence are NOT modeled (at tight base the round
churns faster than the 2x nil gate, so nobody sits still long enough to nil
— live nils need 20s-scale timeouts + dead slots, a richer Byzantine/lock
model than the harness expresses). The sim proves the rate mechanism, not
the full live pathology.

Note: `docs/SIMULATOR.md` §2/§4 table+limits entries for this scenario are
deferred to the merging party — this task's gate forbids touching any file
outside `docs/PROPOSER_REWORK.md`, `stellereum/tests/sim_proposer_*`,
`stellereum/tests/support/*`.

## 5. What a live rollout would require (NOT done here)

1. FLAG (default off = current behavior): e.g.
   `STELL_STRAGGLER_GRACE_MS` / `STELL_STRAGGLER_GRACE_CAP_MS` /
   `STELL_STRAGGLER_FRESHNESS_MS`, all default 0. With 0, the added term is 0
   and the node loop is byte-identical to today.
2. CODE (production, future task): in the node loop, after
   `deterministic_timeout_for` (`stellereum/src/main.rs:960`), add
   `min(grace, cap)` iff fresh straggler evidence (read local `peer_rounds` —
   already maintained — no new state, no wire change); apply the same grace
   to the nil-vote wait. Add metrics: `straggler_grace_extends_total`,
   effective-timeout gauge. No wire-format, quorum, apply, mempool, staking,
   or signature-domain change (frozen core untouched) → no spec fork, no
   coordinated upgrade strictly required; heterogeneous behavior is safe by
   §2(c) design, but roll it coordinated anyway (below).
3. ROLLOUT ORDER: local-cluster reproduction first (shape, not proof) →
   testnet with flag on, one validator → all validators → canary on live
   (single member, the slow one LAST — it benefits least) → fleet. Watch:
   finals rate, RX-log stale-vote share, `grace_extends` rate, view-change
   rate, round-0 QC share. Abort (rollback) if view-change rate rises or
   finals rate drops vs baseline.
4. ROLLBACK: set the three envs to 0 (process restart only — no state
   migration, no data change, no wire incompatibility either direction).
   Risk window is bounded by the cap at all times.
5. TUNING START POINT (from sim proportions, NOT copy-paste): grace ≈ 2x the
   slowest honest member's vote latency, cap = grace, freshness ≈ 5-10x the
   base timeout. Live analogues to measure first: p99 vote-arrival lag per
   member from RX logs.

## 6. Open risks (not closed by this task)

- Byzantine slow-act (bounded stretch to cap every round) needs a
  production-side abuse bound review (cap/freshness picks) before mainnet.
- The `main.rs` timeout-determinism invariant (§2(c)) gets its first scoped
  exception — reviewers must sign off on the "bounded additive execution
  hold" framing.
- Sim does not model nil-storms or lock divergence; a live canary must
  confirm the residual, not just the rate fix.
