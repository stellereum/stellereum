# Liveness audit: round synchronisation and vote coherence

Status: audit note (read-only; no source or test was modified for this report).
Tree audited: `93978950a` (ruleset v5, signed `round` in block identity) **plus** the
uncommitted working-tree delta in `stellereum/src/node/consensus_driver.rs`,
`stellereum/src/runtime/consensus_step.rs` and `stellereum/tests/chase_livelock_tests.rs`.
All `file:line` references are to that tree. Live cluster was not contacted; no node was touched.

Evidence tags used below:

* **[READ]** — established by reading the cited code path.
* **[READ+TEST]** — the cited existing test pins the behaviour described.
* **[INFERRED]** — a deduction from the cited checks; the deduction is written out.

Live facts this audit explains (given): three validators accept and prevote the *same*
block at rounds 505 / 507 / 515; no round reaches quorum; rounds advance ~1 per 3 s
independently; the proposer re-serves the same locked body (same hash, older signed round);
the vote watermark refuses voting at a round `<=` the last voted round.

---

## 0. Verdict

There is no single bug. **Five independent rules each block convergence, and any one of them
is sufficient to hold the height in the live state.** The two that are decisive are:

1. **Votes are stamped with the voter's local round** (`make_vote` → `hc.round`,
   `runtime/consensus_step.rs:1359-1361`), not with the round of the value they vote for.
   Three nodes that accept the same body at three different local rounds therefore produce
   three votes in three different `(height, round)` buckets, and a 3/3 set
   (`consensus_quorum_min(3) = 3`, `consensus/sortition.rs:24-29`) can never form a QC.
   **[READ]**
2. **The rescue re-proposal is served under the body's old signed round on the envelope**
   (working-tree `consensus_driver.rs:2248-2255`), and the outbox prunes proposals
   `SUPERSEDED_ROUND_LAG = 2` rounds behind the sender's round
   (`consensus_net.rs:163, 2982-2987`; `node/policy.rs:1058-1062`). A locked body signed at
   505 re-offered at 515 is therefore **dropped at the sender** and, if it arrives, refused
   by any receiver at round `>= 507` as `"proposal: stale round"`
   (`runtime/consensus_step.rs:1256-1261`). **[READ]**

The other three (round-sync corroboration, future-round alignment, and the send-time
supersede filter) are detailed in §2 and are all required for a durable fix.

The "walls" are:

| Wall | Rule | Where | Effect |
|---|---|---|---|
| W1 | vote round = local round | `consensus_step.rs:1359` | same body, different buckets, no QC |
| W2 | envelope round = body's signed round | `consensus_driver.rs:2254-2255` | rescue proposal pruned at sender / refused at peer |
| W3 | corroboration `count >= 2` | `consensus_step.rs:1023-1027, 1071` | unsatisfiable at N=3 with one node ahead |
| W4 | send prune `< hc.round - 1` | `consensus_net.rs:197-204` | drops the late-round votes the design depends on |
| W5 | alignment keyed on proposer slot, not `block.round` | `consensus_step.rs:1281-1294` | same body accepted by one honest node, refused by another |
---

## 1. The state machine as it is

### 1.1 Round counter

* The only live writers of `hc.round` in steady state are
  `next_round` (`consensus/engine.rs:2288-2333`, `+1` at `:2312`),
  `sync_round_to` (`:2177-2214`, forward jump at `:2208`),
  `apply_deadlock_jump` (`:2618-2628`), and `apply_deadlock_local_reset`
  (`:2730-2764`, `+1` at `:2745`). At startup the restore path writes it too
  (`node/consensus_driver.rs:805, 836-842`).
* `advance_to_round` (`:2434-2446`) has **no production caller** [READ: grep over `src/`
  finds only `src/consensus/engine.rs` itself]. It is a test-only API. The documented
  per-message cap `MAX_ROUND_ADVANCE_PER_MESSAGE = 1` (`engine.rs:31`) therefore does not
  govern any live path, despite being cited as the round-DoS bound in `docs/PENTEST2_CONSENSUS.md:320`.
* `observe_peer_round` (`:2458-2477`) also has **no production caller**; the live vote path
  is `ValidatorRuntime::note_peer_vote_round` (`consensus_step.rs:990-1082`). The two
  implementations of "follow the peer" have already diverged (W3 is enforced on the second
  step in one and on the whole jump in the other).
* Timeout **value**: `deterministic_round_timeout_ms` (`consensus/sortition.rs:944-968`),
  `T(r) = min(base·2^r, base + 10_000ms) + adaptive` with `base = 3_000ms`
  (`sortition.rs:875, 881, 942`). For every `r >= 3` this is the **same 13 s** (plus up to
  5 s of proposer-miss adaptive term). **[READ]** The ladder is deliberately identical on
  every node (`consensus_driver.rs:4409-4430`) and is a local timer only — it never affects
  what is voted.
* **View change**: fires at `round_started.elapsed() > effective_timeout + straggler_hold`
  and `!hold_bounded` (`consensus_driver.rs:4518`), then `next_round()` and
  `round_started = now` (`:4569-4574`). The hold is bounded by `2 * round_timeout` and by
  "a peer at or one round behind us was heard within 2×timeout"
  (`:4375-4408`). A peer strictly *ahead* does not hold us.
* **Nil prevote**: fires at `round_started.elapsed() >= 2 * round_timeout + nil_grace`
  (6 s base), only when no live proposal is held, **and only when no peer was heard within
  `round_timeout` at this height whose round is `>= our_round - 1`**
  (`peer_alive_in_round`, `:2342-2348`, gating `:2373-2379`). The predicate has no upper
  bound on the peer's round, so an **ahead** peer's chatter suppresses our nil indefinitely.
  With the 13 s view change a node therefore casts a nil prevote at 6 s only in a round where
  nobody near is talking; in the live shape (three nodes trading votes at 505–515) the nil is
  suppressed, the round is never voted, and the node's round is never advertised. **Rounds can
  advance without any vote at all.**

### 1.2 Proposal admission (`runtime/consensus_step.rs:1177-1356`)

Order of gates:

1. apply-in-flight → **error, proposal dropped, not deferred** (`:1189-1191`);
2. proposer signature (`:1199-1201`);
3. `validate_proposal_unaligned` (height, timestamp, shard, tx, caps; **no round, no slot**)
   (`:1228`, `:388-...`);
4. actor-cap backpressure (`:1236`);
5. envelope freshness: reject iff `envelope_round + SUPERSEDED_ROUND_LAG <= hc.round`
   (`:1256-1261`);
6. slot alignment **only if the block's proposer is not the proposer of `hc.round`**:
   scan `hc.round+1 ..= hc.round+8` for the **earliest** round whose scheduled proposer is
   `block.proposer`, `sync_round_to` there (`:1269-1295`);
7. slot check against the (possibly moved) `hc.round` (`:1309-1311`);
8. `accepts_block_round`: working tree `block.round <= hc.round` (`:830-832`); HEAD required
   `block.round == hc.round || already_held` (commit `93978950a`);
9. CN-VRF / epoch key / proposer field (`:1327-1344`);
10. `receive_proposal_for(proposer, hash, expected)` — requires `step == Propose`, one value
    per round, and sets `proposal_round = self.round` (`engine.rs:1566-1591`).

### 1.3 Vote emission

* `make_vote` stamps **`self.hc.round`** (`consensus_step.rs:1359-1361`).
  `make_vote_at` exists and is already used for precommits at the polka round
  (`:1476-1529`), but **not** for prevotes.
* Prevote value path: requires `has_live_proposal()` (`engine.rs:1598-1600`,
  `proposal_round == round`), one per round (`last_prevoted`), and
  `!round_at_or_below_vote_floor(vote_floor, height, hc.round)` (`consensus_driver.rs:2977-3011`).
* Prevote nil path: `:2373-2404`.
* Precommit: follows the **polka's** round (`make_vote_at(..., qc_round)`,
  `consensus_step.rs:1510-1528`) and is gated by the watermark on `v.round`
  (`consensus_driver.rs:3465-3469`).
* Vote watermark: write-ahead persisted before broadcast
  (`consensus_driver.rs:61-95`), in-memory floor
  `round_at_or_below_vote_floor` (`:101-103`), raised by `advance_vote_floor` (`:124-133`),
  and a hard floor on restart (`restored_round`, `:118-121`, used at `:805`). It is
  **monotonic and per height**, and it is the only thing that makes re-voting impossible.

### 1.4 Vote admission and quorum

* `add_prevote` / `add_precommit` reject only rounds `> hc.round + 1000`
  (`engine.rs:1626, 1667`) and out-of-scope votes; **any old round is admitted and retained**.
  Vote sets are kept for the whole height: `prune_old_rounds` floor is `0`
  (`:2243-2248`), and the quorum scan reaches `scan_lookback` rounds back
  (`:1753-1785`), up to `REPHASE_SCAN_WINDOW = 4096` (`:1423`).
* Quorum is per `(height, round, kind)`; for N=3 equal-power, `quorum_power = 3`
  (`consensus/sortition.rs:24-29`, `consensus/types.rs:795-816`). **[READ]**
* A polka is recorded the moment the quorum-completing prevote is *admitted*
  (`note_polka`, `engine.rs:2005-2028`), independent of the local round, and it is
  monotonic (`:2014-2016`). A precommit follows `best_polka()` at the polka's own round
  (`consensus_step.rs:1510-1528`).

### 1.5 Round following (the live rule)

`note_peer_vote_round` (`consensus_step.rs:990-1082`):

* ignores `vote_round <= hc.round` (`:1007-1009`);
* `min_supporters = 2` for sets of size >= 3, else 1 (`:1023`);
* `corroborated = supporting_peers_count(vote_round) >= min_supporters`;
* if `!corroborated` and this `(height, vote_round)` was already followed, **return without
  moving** (`:1025-1027`);
* otherwise loop: first step always taken, further steps require corroboration
  (`:1069-1080`); each step is `sync_round_to`, capped at `ROUND_LOOKBACK = 8` per call
  (`engine.rs:2201-2203`), 8 jumps per round (`:1364, 2193-2195`), and a lifetime budget
  `MAX_PEER_ROUND_ADVANCE_PER_HEIGHT = 2048` (`:1391, 2196-2200`);
* every successful jump **clears the live proposal** and resets the step
  (`engine.rs:2209-2211`), which is also why an accepted proposal is wiped by a peer vote.

`supporting_peers_count(r)` counts every validator with `peer_rounds[v] >= r`
(`engine.rs:2504-2506`); `peer_rounds` is written for **every verified same-height vote**,
accepted or not (`consensus_step.rs:1109`), and is monotonic per voter
(`engine.rs:2496-2501`).

### 1.6 Send policy (the invisible filter)

* `flush_outbox(..., hc.height, hc.round)` (`node/policy.rs:1048-1062`) drops any vote with
  `vote.round + 2 <= hc.round` (`consensus_net.rs:197-204`) and any proposal with
  `proposal.round + 2 <= hc.round` (`consensus_net.rs:2982-2987`). Every production flush
  site passes `rt.hc.round` (`consensus_driver.rs:1402, 1445, 2259, 2302, 2728, 2783,
  3000, 3479, 4318, 4565, 4597, 4767, 4775`; verified exhaustively by grep).
* Unit test `superseded_votes_drop_without_touching_proposals_or_commits`
  (`consensus_net.rs:6063-6102`) **pins the false premise** that "a vote two rounds old at
  the same height is worthless (no quorum can form there anymore)" — while §1.4 shows old
  rounds are retained, scanned to 4096, and are exactly what the late-polka design relies on.

---

## 2. Findings (detailed)

### F1 — BLOCKER: the vote's round is the node's round, not the value's round

**[READ]** `consensus_step.rs:1359-1361` (`make_vote` → `hc.round`), consumed at
`consensus_driver.rs:2986` and `:2380`. `proposal_round` records the *local* round
(`engine.rs:1589`), so `has_live_proposal()` is true for a body signed at 505 held at 515.

Exact failing state, matching the live fact pattern:

```
h = H, N = 3, quorum = 3
A: round 505, accepts body B (B.round = 505) → prevote (H, 505, Prevote, B)
B: round 507, accepts body B (B.round = 505) → prevote (H, 507, Prevote, B)
C: round 515, accepts body B (B.round = 505) → prevote (H, 515, Prevote, B)
```

Every node is honest, every vote names the same hash, and **no `(H, r)` bucket ever holds
more than one vote** — `VoteSet::quorum_target` is `None` for all three rounds (used at
`engine.rs:2106-2112`; the set is keyed by round at `engine.rs:1227-1228` and quorum is
computed within one set). **[INFERRED from that per-round arithmetic.]**

### F2 — BLOCKER: the rescue envelope is the body's signed round; the outbox deletes it

**[READ]** Working-tree `consensus_driver.rs:2248-2255`:

```rust
compact_server.remember(&block, block.round);
let msg = stellereum::consensus_net::proposal_gossip_msg(&block, block.round);
```

For a locked re-proposal the body is returned **verbatim** by `propose`
(`runtime/mev_sync.rs:936-965`, `:977-1020`), so `block.round` is the *original* signed
round. Consequences:

1. Sender: `flush_outbox(..., rt.hc.round)` (`:2259`, and every periodic flush) drops the
   frame as `is_superseded_proposal` whenever `block.round + 2 <= hc.round`
   (`policy.rs:1061`, `consensus_net.rs:2982-2987`). A locked body signed at 505 proposed
   at 515 **never leaves the process**.
2. Receiver: even if it escapes (the periodic retransmit at `:4757` uses
   `proposal_gossip_msg(&b, rt.hc.round)` — the *current* round — so the two emission sites
   disagree), any receiver at round `>= block.round + 2` refuses it as
   `"proposal: stale round"` (`consensus_step.rs:1256-1261`).
3. The compact body server is keyed by `(hash, height, round)` and a pull only resolves
   on an **exact** round match (`consensus_net.rs:3365-3368`). The initial announce remembers
   the body under `block.round` (`driver:2254`) while the periodic retransmit remembers the
   same body under `rt.hc.round` (`:4756`), so the two emission sites overwrite each other's
   key and a `BodyPull` echoing the other round misses.

The comment at `:2248-2253` states the opposite of the code's behaviour ("every peer would
refuse the frame as `stale round` while the signed block was current"). The comment is
correct about the *body* and wrong about the *envelope*: the envelope names the round the
proposal is **for**, which for a re-proposal is the proposer's current round, not the
round the body was first signed under.

This alone reproduces the reported symptom ("the proposer re-serves the same locked body —
same hash, older signed round") and guarantees the stall: the value is never delivered, so
the only votes that can form are nil.

### F3 — BLOCKER: `count >= 2` corroboration is unsatisfiable at N=3 with one node ahead

**[READ]** `consensus_step.rs:1023-1027` and `:1069-1080`; `engine.rs:2469-2473` (the same
rule in the dead `observe_peer_round`).

Let the network be at `R` on one validator and at `R - d` on the other two, with `d > 8`.
For a behind node:

* `supporting_peers_count(R) = 1` (only the ahead validator is at/above `R`; a validator at
  `R - d` is not, and the node's own self-report at `R - d` is not either).
* The first jump is allowed and moves `+8`; `last_followed_round := (H, R)`.
* The **second** step at the same target requires `count >= 2`, which is false, and the
  dedup path (`:1025`) refuses to re-open the chase for a repeated `(H, R)`.
* A *new* target `R+1` (the ahead node's next vote) is a new key, so the node gains another
  `+8`. The chase rate is therefore **8 rounds per ahead-round**; the escape rate is
  **1 round per ahead-round** (the ahead node's own timeout). That converges only while
  the ahead node keeps emitting a vote every round.

The rule is not automatically fatal on paper — but it is fatal in the live shape for three
reasons:

1. The ahead node only votes once per round and then **falls silent for the rest of the
   round** (`last_prevoted` dedup, `:2979`); its next vote is a nil at `2×timeout`, and that
   nil is itself **suppressed while a peer at/above `our_round - 1` was heard inside
   `round_timeout`** (`peer_alive_in_round`, `:2342-2348, 2377`). In a chattering 3-node
   cluster the nil is therefore never sent, and the ahead node's next advertised round can be
   many rounds later. During that window the behind node has no new target.
2. A node that was pulled to `R` clears its proposal and resets `round_started`
   (`:3189`); it has just heard the peer vote, so its own nil at `R` is suppressed by
   `peer_alive_in_round`. The middle node therefore does **not** vote at `R`, its arrival is
   invisible, and `supporting_peers_count(R)` stays 1 for the last node.
3. The ahead node's vote at `R` is the *only* thing that advertises `R`; if the vote stream is
   thinned by the send prune (§1.6/F4) or by the nil suppression, the chase has no new key and
   the `+8` it already got is all it will ever get.

**Answer to the direct question:** with N=3 and exactly one node ahead, `supporting_peers_count(target) < 2` is **unsatisfiable for the target that is more than `ROUND_LOOKBACK` ahead**, because reaching 2 requires a *second* validator already at/above the target, i.e. it presupposes the convergence it is supposed to cause. The rule is a liveness gate that can only confirm convergence after the fact. (The project already documented the shape: `consensus_driver.rs:4395-4397` — "in a 3-validator set the two nodes BEHIND could never gather two supporters and never caught up — a different deadlock".)

The correct BFT bound for this gate is **`f + 1`**, not a constant 2:
`f = floor((n-1)/3)` for equal power, so N=3 → 1 supporter, N=4 → 2, N=7 → 3. A count of 2
is *below* the fault bound for N >= 7 (three colluding validators out of nine are below
one third and must not corroborate) and *above* f+1 for N=3. `docs/REVIEW_CONSENSUS.md:353`
already says the correct threshold is `f + 1`; the code never adopted it for this call site.

`ROUND_LOOKBACK` is **not** the binding cap here: `note_peer_vote_round` loops, so a gap of
10 or 64 is reachable in one call. The binding caps are the corroboration gate and the
per-round jump budget. The 8-round per-call cap in `observe_peer_round`/`sync_round_to` only
matters for the dead API.

### F4 — HIGH: the send-time supersede filter deletes the votes the protocol needs

**[READ]** Details in §1.6. This is not just a rescue-path issue: `make_precommit` casts at
the **polka's** round (`consensus_step.rs:1528`), which is routinely below `hc.round`; the
flush at `consensus_driver.rs:3479` passes `hc.round`, so a precommit for a polka more than
one round back is **dropped on the wire**. The whole late-polka ledger (`engine.rs:1297-1320,
2005-2028`) and the re-phase scan window (`:1423`) exist so that a late quorum can still
decide; the send filter undoes them. This matches the historical "prevote QC present, no
precommit ever cast" shape that the code comments say was fixed
(`consensus_step.rs:1477-1509`).

### F5 — HIGH: future-round alignment targets the proposer's earliest slot, not `block.round`

**[READ]** `consensus_step.rs:1269-1295` + `:1319-1324`.

If a genuine block is signed at round `q > hc.round`, the alignment loop scans
`hc.round+1 ..= hc.round+8` for the **earliest** round owned by `block.proposer` and syncs
there. That earliest round can be `< q` (each round's proposer is an independent
hash draw, `engine.rs:1538-1545`), after which `accepts_block_round` refuses the block
(`block.round = q > hc.round = r_earlier`). If `block.proposer` happens to be the proposer
of the *current* round, the alignment does not run at all and the block is refused
immediately. **[INFERRED from the two branches: alignment runs only on `proposer != expected_now`,
and acceptance requires `block.round <= hc.round`.]**

The existing test `proposal_phase_align_accepts_next_round_and_votes`
(`tests/chase_livelock_tests.rs:96-140`) only exercises `q = hc.round + 1` with the peer
owning `q`, the one case where "earliest slot" == `q`. It does not cover a block signed
several rounds ahead, so the mis-target is untested.

**State where two honest nodes accept the same body but cannot vote in the same round**
(the question asked in the brief):

* A at 505 receives body signed at 515, proposer owns 505 → no alignment, `515 <= 505`
  false → **refused**.
* B at 507 receives the same bytes, proposer does not own 507 → aligns to the earliest slot,
  say 508, `515 <= 508` false → **refused**.
* C at 515 receives them, `515 <= 515` → **accepted and votes at 515**.

Three honest nodes, one body, three different verdicts. Even when all accept, the vote round
is each node's `hc.round` (F1), so acceptance and vote coherence are independent failures.

### F6 — HIGH: round state propagates only through votes, and the "sit while armed" rule is a stale comment

**[READ]** `consensus_driver.rs:3179-3181` claims: "`note_peer_vote_round` skips the jump
while we hold a live proposal for a near round (accept-wipe livelock)". The implementation
(`consensus_step.rs:990-1082`) contains **no such skip**; the comment at `:1000-1006`
explicitly says a "sit-while-armed variant was tried … and reverted". So the driver's
behavioural contract is documented wrong: any verified vote ahead **does** wipe the live
proposal (`engine.rs:2209-2211`) and move the round. This is the "skip the jump while holding
a live proposal" rule the brief asks about: **it does not exist.** Its absence is what makes
the round chase and the proposal acceptance fight each other (accept at `r`, get pulled to
`r+8`, proposal wiped, accept again at `r+8`, vote at `r+8`).

Round information reaches peers **only** via votes (`observe_peer_vote` → `note_peer_round`,
`consensus_step.rs:1109`). A node with no proposal casts a nil only at `2×timeout`
(`consensus_driver.rs:2373-2379`), **and only when no peer at/above `our_round - 1` was heard
inside `round_timeout`** (`:2342-2348, 2377`). After a sync the node has just heard exactly
such a vote, so its nil is suppressed, its `round_started` was reset (`:3189`), and it times
out at 13 s and moves again — without ever advertising the round it left. The observation
"rounds advance ~1 per 3 s independently" is consistent with per-node timer drift plus this
silence. **[INFERRED; the driver resets `round_started` on every accepted/reraised round at
`:3093` and `:3189`, so an incoming vote stream can indefinitely postpone the 6 s nil wait.]**

Note also that the effective timeout **plateaus** at `base + 10 s` for every `r >= 3`
(`sortition.rs:955-956`). An ahead node and a behind node therefore advance at the **same**
rate; the ladder provides **no mean reversion**. Tendermint's `2^r` ladder (uncapped or
capped far above the working range) is what makes a lone ahead node wait long enough for the
rest to catch up. The cap is the direct reason the gap does not close on its own.

### F7 — MEDIUM: an in-flight apply destroys a proposal instead of deferring it

**[READ]** `on_proposal` returns `Err("proposal deferred: apply in flight")`
(`consensus_step.rs:1189-1191`) and the driver's `Err` arm only logs
(`consensus_driver.rs:3013-3023`). The block is **not** re-queued. During a slow apply
(snapshot/state-root work) every incoming proposal for the height is discarded; the
proposer re-sends on the 600 ms retransmit, but if the apply outlasts the round the
proposal is lost and the node nil-votes. The H+1 deferral path (`:2902-2911`, `:3049-3058`)
shows the intended pattern (defer, do not drop); the same-height path does not use it.

### F8 — MEDIUM: `has_live_proposal()` can be true for a value whose round is already burned

**[READ]** `has_live_proposal` is `proposal_round == round` (`engine.rs:1598-1600`), with no
reference to the vote floor. After a node nil-votes at round `r`, it can still accept a
re-proposal into `r` (if `step == Propose` and no proposal is recorded) and then
`has_live_proposal()` is true, `make_prevote()` would return a value vote, and the driver's
floor check (`consensus_driver.rs:2980-2984`) suppresses it. The node is left holding a
proposal it can never vote and the propose gate is closed for the round
(`:2172`). It will time out and clear it, one round later. This is a wasted round per
occurrence and a source of the "accept-then-silence" behaviour.

### F9 — MEDIUM: a bodyful lock can never be released, and the re-phase refuses to drop it

**[READ]** `apply_deadlock_local_reset` drops the lock only when the body is **absent** and
no precommit QC was observed (`engine.rs:2730-2742`); the code itself flags the consequence
at `:2713-2722`. If a node holds the locked body and the value's signed round `q` is already
below the local vote floors of the set (every validator has signed some vote at a round
`> q`, nil or value — the live shape), the value can never gather a QC at `q`, the lock never
clears, and `decide_prevote` nils every other value (`engine.rs:1604-1617`). With N=3
unanimity, one such lock wedges the height. This is the same shape
`tests/bft_lock_safety_tests.rs:287-299` pins as a known limitation and says must be deleted
"when the `validRound` mechanism lands".

### F10 — LOW: nil-round accounting counts sync jumps as failed rounds

**[READ]** `next_round` classifies the round it leaves by whether `prevotes[left]` has a
block QC (`engine.rs:2288-2297`). A node that jumped over `left` via `sync_round_to` never
voted there, so the round counts as nil, `consecutive_nil_rounds` grows, and the nil breaker
can fire spuriously (`:2353-2358, 2393-2406`). The breaker itself is safe (widens the scan
window once, casts no vote, moves no round), but it pollutes the liveness signal an operator
would use to diagnose this exact stall.

### F11 — DOC: claims that are no longer true

* `consensus_driver.rs:3179-3181` (skip-while-armed, see F6).
* `docs/PENTEST2_CONSENSUS.md:320-321`: "No path moves our round from a raw peer claim …
  A stale proposal after a round change is refused … envelope round is only a stale check."
  The working tree moved `accepts_block_round` to `<=` and the envelope check to a 2-round
  lag, so a stale body **is** now accepted (by design) and the envelope **does** select an
  accept round. The paragraph must be rewritten with the fix.
* `docs/CONSENSUS_SYNC.md:135` cites `consensus.rs` line numbers that now live in
  `consensus/engine.rs`; the numbers there are stale.
* `docs/REVIEW_CONSENSUS.md:333-343` describes a `breaker_corroboration()` function that no
  longer exists under that name.
* `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md` §2 cites `sortition.rs:719/650/656/717` for
  the ladder and cap; the current lines are `944-968/875/881/942`. The constants agree, the
  citations do not.

---

## 3. Safety analysis of the candidate rules

The safety property to preserve is: **one decision per height, and no validator signs twice
for the same `(height, round, kind)`** (the watermark is the enforcement; the lock is the
value-level guard). A "round move" is never a safety action — it only decides which bucket
our next vote lands in. Therefore:

| Candidate rule | Double-finality | Vote below watermark | Future-round acceptance | Proposal-slash evidence | Verdict |
|---|---|---|---|---|---|
| **Rewind `hc.round`** to the value's round | No direct risk | **Breaks**: re-entering a round we signed is a self-equivocation, and the persisted floor (`driver:118-121, 805`) would be violated | n/a | no change | **FORBIDDEN** |
| **Vote at `block.round`** (R-A) | Safe: one vote per `(h,q,kind)`; the watermark still blocks a second | **Safe only if gated by `round_at_or_below_vote_floor`**; otherwise it *is* a double vote | No (q <= hc.round) | unchanged; a re-proposal at an older q is still not evidence | Safe but **insufficient**: a `q` below the local floor cannot be re-entered (a node that voted at its own higher round can never vote at `q`) |
| **Chase without corroboration** (R-C) | None: moves no vote, no lock, no value | n/a | No (forward only) | None | **Safe**; the only risk is liveness/DoS, already bounded by `MAX_PEER_ROUND_ADVANCE_PER_HEIGHT = 2048` and recoverable because `2048 < REPHASE_SCAN_WINDOW = 4096` (`engine.rs:1382-1391, 1423`) |
| **Re-stamp the locked value at the proposing round; lock by value id** (R-B) | **Safe**: the two hashes commit to identical height/parent/state-root/tx-order and differ only in the round tag; applying either is the same state transition, and `try_finalize` decides at most once per height (`engine.rs:2106-2158`); `adopt_committed` binds height+certificate (`runtime/consensus_step.rs:2291-2326`) | n/a (we vote at the current round, which is above the floor) | No: the re-stamped body is signed at `hc.round` | unchanged: two proposals are evidence only at the **same** signed round with different hashes | **Safe and sufficient** |
| **Timeout differential for ahead nodes** (R-D) | None (timers are time-free, `consensus_driver.rs:4409-4418`) | n/a | n/a | None | **Safe** (local policy) |

Two safety notes that matter for the implementer:

1. **The watermark must gate on the round the vote actually names, in every path.** Under R-A
   the vote round is `block.round`; under R-B it is `hc.round`. The current driver correctly
   gates prevotes on `hc.round` (`:2980-2984`) and precommits on `v.round` (`:3465-3469`), but
   any new call site must not assume "the vote's round is `hc.round`". Keep one helper:
   `may_vote(floor, h, vote_round)`.
2. **Never let the send prune decide safety-adjacent semantics.** `is_superseded_vote`
   (`consensus_net.rs:197-204`) currently deletes votes the engine deliberately retains. It
   is a bandwidth optimisation and must be keyed on the **scan floor**
   (`engine.rs:1780-1785`), not `hc.round`, or it will keep deleting exactly the votes a
   late-polka decision needs.

---

## 4. Rule sets that restore convergence

Three candidate sets, ordered by blast radius. All are local rules (no wire-format field is
added); R-B changes a *consensus validation rule* and therefore needs a spec update + audit
note + activation height per `AGENTS.md` §7.

### Rule set R-A — "vote in the value's round" (smallest diff, insufficient)

1. Keep the working-tree `accepts_block_round: block.round <= hc.round`
   (`consensus_step.rs:830-832`).
2. Record the accept round as `block.round`: add
   `receive_proposal_at(proposer, hash, round)` and set `proposal_round = round` instead of
   `self.round` (`engine.rs:1589`).
3. `make_prevote` stamps `proposal_round`, not `hc.round` (`consensus_step.rs:1359-1361`).
4. The prevote gate compares `proposal_round` to the watermark; if it is at/below the floor,
   **do not vote** (and do not clear the proposal; it can still be precommitted from the
   polka ledger).
5. Fix the send prune to use the scan floor (§5).

**Why it is not enough:** the watermark floor is the **maximum** round at which the node has
signed *any* vote (prevote or precommit) at this height (`storage.rs:2199-2210`,
`consensus_driver.rs:101-103`). Every node that has already voted at a round `> q` — including
the value vote at its own local round that this very stall produces — is barred from voting at
`q`. In the live facts all three nodes voted the block at 505 / 507 / 515, so only the node
sitting exactly at `q = 505` may vote at 505; the other two are already above the floor and
can never come back down. R-A therefore collapses three buckets into **one** vote in the
lowest node's round, not a quorum. It is safe, and it removes the split, but it does not
restore liveness for a value whose round is already behind most of the set. **Do not ship R-A
alone.**

### Rule set R-B — "validRound by re-stamping" (recommended)

This is the mechanism the codebase already names in
`tests/bft_lock_safety_tests.rs:287-299` ("must be deleted … when the `validRound`
mechanism lands").

1. **Re-stamp on rescue.** In `propose` (locked path `runtime/mev_sync.rs:936-965`, demanded
   path `:977-1020`) copy the body, set `round = hc.round`, clear `validator_signatures`,
   re-sign. The body hash changes; the value does not.
2. **Value identity.** Add `fn value_id(b: &Block) -> [u8; 32]` = `compute_hash` of the body
   with `round := 0` (the hash already zero-skips the round section, `sharding/block.rs:946-949`,
   so this is the existing bytes with the tag omitted). Use it **only** in the lock rules:
   `decide_prevote` (`engine.rs:1604-1617`), the unlock check in `try_prevote_quorum_at`,
   and the precommit lock guard (`consensus_step.rs:1520-1524`) compare `value_id`, not the
   hash, and require the new body's round `>` the lock round.
3. **Vote at the current round.** Unchanged `make_vote` (`hc.round`). The tuple
   `(height, round, value)` is Tendermint's; the value's identity no longer encodes the round.
4. **Proposal round is explicit.** The envelope carries `rt.hc.round` (the round being
   proposed for), not `block.round` — this is the F2 fix, and it also makes the sender and
   receiver agree on freshness.
5. **Align to `block.round`.** In `on_proposal`, when `block.round > hc.round` and
   `block.round <= hc.round + PROPOSAL_ALIGN_WINDOW_ROUNDS`, `sync_round_to(block.round)`
   and then require the proposer to own **that** round (not the earliest slot). Refuse
   future blocks outside the window. This is the F5 fix.
6. **Out-of-phase proposer.** The body's author is fixed (it is `block.proposer`), so only
   that validator can re-propose it. It must therefore re-stamp at its **own current** round
   after it has caught up to the network (the existing verified-vote chase does that within
   its budgets); if it is not the scheduled proposer of the round it would need, it stays
   silent and re-proposes when its slot comes round again. This is why R-C is a mandatory
   companion: without it the author cannot catch a set that is more than `ROUND_LOOKBACK`
   ahead, and it will never own a slot at their round.
7. **Never drop a live proposal for a vote that does not move us**, and never clear it on a
   re-entrant `on_proposal` for the same value (the one-value guard at `engine.rs:1582-1586`
   already returns `Ok` for the identical body at the same round — keep it).

**Safety argument (R-B):** the two hashes of one value commit to the same height, parent,
state root, timestamp and tx order; only the round tag differs. A QC for either is a
certificate for the same state transition, and a height decides once
(`try_finalize`, `engine.rs:2106-2158`; `decided` is checked before apply). The lock is
preserved because a node locked on value `V` at `r0` will vote `V` at any `r > r0`, and
will still refuse any **different** value. The one-value-per-round rule
(`engine.rs:1582-1586`) and the watermark are untouched, so no double-sign and no
double-propose evidence change. A voter always holds the exact re-stamped body it voted —
`on_proposal` inserts it (`consensus_step.rs:1354`) before any vote is cast — so finality
never needs to fetch a hash it cannot reconstruct. **No fork risk for the value; a
rule-change activation is still required** because a node that does not compare `value_id`
would nil the re-stamped body (liveness, not safety, and the live cluster is stopped).

### Rule set R-C — "f+1 corroboration" (mandatory companion, one line)

Replace the constant `2` in `consensus_step.rs:1023` (and the dead twin in
`engine.rs:2469-2473`) with the BFT bound:

```rust
let f = (self.validators.len() - 1) / 3;   // equal-power sets
let min_supporters = f + 1;                // N=3 -> 1, N=4 -> 2, N=7 -> 3
```

(or the power-weighted analogue `3 * supporting_peer_power(r) > total` already used by
`corroborated_round`, `engine.rs:2527-2530`, with the threshold taken on the **reporter
power**, not the quorum power). A count of 2 is simultaneously too strict for N=3 and too
weak for N>=7; `f+1` is correct on both ends.

**Safety:** the gate only ever decides whether to move our **own** round forward; it never
selects a value. The DoS concern it was built for is a liveness concern ("drag the node off
the network"), and the per-height budget `MAX_PEER_ROUND_ADVANCE_PER_HEIGHT = 2048`
(`engine.rs:1391`) already bounds that, while `REPHASE_SCAN_WINDOW = 4096` (`:1423`) keeps
the network's true round committable. `MAX_DEADLOCK_JUMP = 65536` (`:1406`) is the escape
hatch. So relaxing the gate inside that envelope cannot cost safety.

### Rule set R-D — "mean-reverting timeout" (optional, addresses the plateau)

The timeout ladder is identical for an ahead and a behind node once `r >= 3`
(`sortition.rs:955-956`), so a round gap is a random walk with no restoring force. Either

* raise/remove `DETERMINISTIC_BACKOFF_CAP_MS` (10 s, `sortition.rs:881`) so `2^r` still
  differentiates the live round range, or
* add a **node-local** term proportional to `round.saturating_sub(max_peer_round)` (the
  node's lag relative to verified peer rounds). This makes an ahead node wait longer and a
  behind node shorter.

**Safety:** the timeout never enters what is signed; it only moves our own round
(`consensus_driver.rs:4409-4418` states this explicitly). A node-local term is therefore
time-free in the safety sense even though it diverges across nodes; the only cost is that
two honest nodes no longer compute the identical duration, which the frozen spec
(`docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2 §2`) currently forbids. Treat R-D as a spec
change, not a hotfix; R-B + R-C do not need it.

---

## 5. The three other required fixes (independent of the rule set)

**S1 — envelope = the round being proposed for.** Revert
`consensus_driver.rs:2254-2255` to `rt.hc.round` (or the tick-local `round`), and make the
periodic retransmit (`:4757`), the view-change re-send (`:4553`) and the nil breaker
(`:4595`) all use the same value. A body's signed round stays in the hash; the envelope is
a claim about the *proposal*, not the value.

**S2 — send prune keyed on the scan floor.** `flush_outbox` must not use `hc.round` as the
prune anchor. Pass `rt.hc.scan_floor()` (or a new `vote_is_still_useful(height, round, floor)`
helper) so a vote is only dropped when its round is below the range the quorum scan can still
reach (`engine.rs:1780-1785`), and a proposal is only dropped when it is below the range the
receiver could still accept. This single change unblocks the late-polka precommit
(`consensus_step.rs:1528` → `driver:3479`) and any R-A/R-B vote at a settled round. The unit
tests at `consensus_net.rs:6063-6102` and `:6105-6131` pin the old premise and must be
rewritten (not weakened) with the new invariant: *a vote at a round the scan still reaches
must survive the outbox*.

**S3 — defer instead of dropping a same-height proposal while apply is in flight.** Reuse
the `inbound_deferred` lane (`consensus_driver.rs:2902-2911`) in the `Err("proposal
deferred: apply in flight")` arm (`:3013-3023`), exactly as the H+1 arm does.

---

## 6. Tests that distinguish the rule sets

All are deterministic; none needs a live node. "Before" is the current tree; "after" is the
stated rule set.

> Note (read-only, observed while auditing): an untracked
> `stellereum/tests/live_stall_repro_tests.rs` appeared in the tree during this audit. Its
> `same_body_prevoted_at_three_rounds_is_the_live_stall` already pins the **F1 mechanism**
> (same hash, three prevote rounds, no quorum) and its ignored
> `same_body_converges_to_one_round_and_finalises` is the desired post-fix property. T1 below
> is the pure-arithmetic companion to it; T3/T10 are the R-B-specific tests it does not
> contain. That file was not read for correctness and is not part of this audit's evidence.

### T1 — quorum arithmetic: same body, same bucket

`tests/round_coherence_tests.rs::same_hash_three_rounds_never_reaches_quorum`
Build one `HeightConsensus` with a 3-member equal set; add three genuine Falcon prevotes for
the same hash at rounds 505, 507, 515. Assert
`prevotes[r].quorum_target(&vs) == None` for each `r`, and
`add_prevote` of three votes **at one round** yields `Some(Some(hash))`.
*Pins the claim in F1; passes before and after — it is the arithmetic the fix must respect.*

### T2 — vote round is the value's round (R-A)

`tests/round_coherence_tests.rs::prevote_round_equals_the_value_round`
Three `ValidatorRuntime`s; call `on_proposal` with the same body (`block.round = q`) while
their local rounds are `q, q+2, q+10` (use `hc.next_round()` to reach those; arrange the
proposer schedule so the body's author owns each local round, or call the new
`receive_proposal_at` directly — `on_proposal` still enforces the slot at `hc.round`). Assert
each `make_prevote().unwrap().round == q` and `block_hash == hash`.
*Before (R-A):* fails (votes at `q`, `q+2`, `q+10`). *After R-A:* passes. *After R-B:* fails
by design (the vote is at the proposer's round, and the bodies are re-stamped per round) —
so **T2 selects R-A over R-B**.

### T3 — a value below the local floor is not re-votable (R-A vs R-B discriminator)

`tests/round_coherence_tests.rs::value_below_the_watermark_is_not_revotable`
Node votes at round `q+2` (value or nil; raise the watermark floor), then `on_proposal` of
the locked body signed at `q` arrives at local round `q+2`. Assert:
`on_proposal` may be `Ok` (admission), but **no** prevote is produced at `q`
(`round_at_or_below_vote_floor(floor, h, q)` is true, so the driver gate is false) and the
floor is unchanged. Then re-propose under R-B at `q+3`: assert a **new** hash is produced
(`new_hash != locked_hash`), `value_id(new) == value_id(locked)`, and the node **does** vote
it at `q+3`.
*Before:* no `value_id` exists → compile-level distinction. *After R-A:* the second half
fails (the body hash is unchanged and the vote would be at `q`, blocked by the floor) →
**R-A cannot pass T3**. *After R-B:* passes.

### T4 — the rescue proposal is actually sent and accepted (F2/S1)

`tests/round_send_policy_tests.rs::rescue_proposal_envelope_is_the_proposing_round`
With a local round of 515, locked body signed at 505, assert
`proposal_gossip_height_round(&proposal_gossip_msg(&body, 515)) == Some((h, 515))`, then
`flush_outbox(&mut outbox, h, 515)` does **not** drop it. Feed the same frame to a peer at
507 and assert `on_proposal` returns `Ok`.
*Before:* fails (envelope `(h, 505)` → pruned at `policy.rs:1061` and refused at
`consensus_step.rs:1256-1261`). *After S1:* passes.

### T5 — late-round votes and precommits survive the outbox (S2)

`tests/round_send_policy_tests.rs::late_polka_precommit_is_not_pruned`
Precommit at round 10, local round 20, scan floor 0. Assert
`flush_outbox(..., 20)` delivers it (or `is_superseded_vote(&msg, 20, /*floor*/ 0) == false`).
*Before:* fails. *After S2:* passes. *Kills the premise in `consensus_net.rs:6064-6075`.*

### T6 — N=3 corroboration fixed point (R-C)

`tests/round_sync_audit_tests.rs::one_ahead_validator_is_unsatisfiable_at_n3`
Pure `HeightConsensus`: set `peer_rounds = {C: 515}`, `round = 505`. Assert
`observe_peer_round(C, 515)` moves to 513 and `supporting_peers_count(515) == 1`. Add
`peer_rounds[B] = 515`; assert a second call moves to 515.
*Before:* the first half pins the failure. *After R-C:* `observe_peer_round` should reach
515 with one reporter (the test flips).

### T7 — future proposal aligns to its signed round (F5 / R-B step 5)

`tests/proposal_alignment_tests.rs::future_block_aligns_to_block_round_not_earliest_slot`
3 nodes; find a round `r` where `block.proposer` owns `r+1` **and** `r+5`, build the body
at `r+5`, call `on_proposal` from a node at `r`. Assert `hc.round == r + 5` and
`make_prevote().round == r + 5`.
*Before:* fails (aligns to `r+1`, then `"block round 5 does not match proposal round 1"`).
*After R-B (step 5):* passes.

### T8 — deliverability under a silent ahead node (F6/R-D)

`tests/consensus_liveness_harness.rs::three_validators_one_ten_rounds_ahead_still_finalizes`
Profiles `[default, default, ahead_by(10)]` (the harness has `late_by`, `consensus_cluster.rs:341-345`;
add the symmetric `ahead_by` setter there — a test-support-only change). Run to height 2 and
assert `best_height >= 2`, `common_height == best_height`, no double votes
(`assert_global_invariants`), and `nodes[2].sync_jumps == 0` (the ahead node must not be
pulled; the two behind nodes must close the gap).
*Before:* expected to stall (this is the live shape; the existing suite only covers
"one node 30 rounds **behind** two agreed peers",
`consensus_liveness_harness.rs:257-303`, which the `count >= 2` gate *can* satisfy because
two validators are at the target). *After R-B + R-C:* passes.

### T9 — watermark is never violated by any convergence rule

Module unit test `node/consensus_driver.rs::tests::no_path_emits_a_vote_at_or_below_the_floor`
(the helper `round_at_or_below_vote_floor` is private, so this lives beside it). For
`floor = 515`, assert no call site returns a vote round `<= 515` for `(h, Prevote)` /
`(h, Precommit)` — call `make_prevote` and `make_precommit` in the states T2/T3 construct and
assert `v.round > 515` or `v.is_none()`. This is the regression guard for every rule set
above; it must pass before and after.

### T10 — no double finality under re-stamping (R-B)

`tests/bft_lock_safety_tests.rs::restamped_value_cannot_double_decide`
Two hashes `H1 = body@r1`, `H2 = body@r2` with `value_id(H1) == value_id(H2)`. Feed a
precommit QC for `H1` to one node and for `H2` to another at the same height. Assert:
`try_finalize` decides at most once per height, `decided` never changes after being set, and
`hc.equivocations()` (`engine.rs:2767-2776`) reports **no** proposal pair (different signed
rounds are not evidence). *Before:* compile-level (no `value_id`). *After R-B:* must pass.

### T11 — restart never rewinds below the watermark (existing invariant, re-pin)

Module unit test `node/consensus_driver.rs::tests::restored_round_respects_the_vote_floor`
(`restored_round` is private):
`restored_round(0, Some(515)) == 515`; `restored_round(10_000, Some(515)) == 515`;
`restored_round(10_000, None) == MAX_RESTORED_ROUND` (= 64, `:111`). Pins
`consensus_driver.rs:118-121` against any rule set that proposes to move `hc.round`
backwards.

---

## 7. Recommended minimal fix (for the F1 implementer)

**Do R-B + R-C + S1 + S2 (+S3), not R-A, and not any round rewind.**

1. `propose` re-stamps a locked/demanded body at `hc.round` and re-signs it
   (`runtime/mev_sync.rs:936-965, 977-1020`); the lock rules compare `value_id`
   (hash with `round := 0`) instead of the hash (`engine.rs:1604-1617`,
   `consensus_step.rs:1520-1524`), requiring `new_round > locked_round`.
2. The proposal envelope always names `rt.hc.round` (`consensus_driver.rs:2254-2255, 4553,
   4757, 4595`), never `block.round`.
3. `on_proposal` aligns to `block.round` (bounded by `PROPOSAL_ALIGN_WINDOW_ROUNDS`) when it
   is in the future, and accepts a past `block.round` only as a value; the vote is cast at
   `hc.round` (Tendermint tuple semantics).
4. `min_supporters = f + 1` in `note_peer_vote_round` (`consensus_step.rs:1023`) and in the
   dead twin (`engine.rs:2469-2473`); leave both budgets
   (`MAX_SYNC_JUMPS_PER_ROUND = 8`, `MAX_PEER_ROUND_ADVANCE_PER_HEIGHT = 2048`) untouched.
5. `flush_outbox` prunes by the **scan floor**, not `hc.round` (`node/policy.rs:1048-1062`);
   rewrite the two unit tests that pin the old premise.
6. Defer same-height proposals while apply is in flight instead of returning an error
   (`consensus_step.rs:1189-1191` → `consensus_driver.rs:3013-3023`).
7. Delete or correct the stale comment at `consensus_driver.rs:3179-3181` and the stale
   claim in `docs/PENTEST2_CONSENSUS.md:320-321`; the "skip the jump while holding a live
   proposal" rule does not exist today and must not be reintroduced silently.

**Why this is safe:** (i) a re-stamped value commits to the same height, parent, state root
and tx order, so a QC for either hash is a certificate for the same state transition and a
height still decides once; (ii) the watermark still forbids a second vote at any
`(height, round, kind)`, and every vote is at the current round, strictly above the floor;
(iii) no round ever moves backwards, so no self-equivocation and no restart-floor violation;
(iv) future signed rounds stay refused; (v) proposal-slash evidence is unchanged because it
requires the **same** signed round with different hashes, and a re-stamp changes the signed
round by design. The only new consensus rule is the `value_id` lock comparison; per
`AGENTS.md` §7 it needs a spec update + audit note + activation height, but it is not a
wire-format change and the stopped cluster can adopt it directly.

**Why R-A alone is not acceptable:** the watermark floor is the highest round at which the
node has signed *any* vote at this height (`storage.rs:2199-2210`), and in the live shape
every node has already voted the body at its own (higher) round. A value signed at `q` can
therefore only be voted by nodes whose floor is `< q`; under 3/3 unanimity the rest can never
re-enter `q` without a self-equivocation, and the height stays parked. The `validRound` shape
is the one the codebase already says makes this class converge
(`tests/bft_lock_safety_tests.rs:287-299`).

---

## Appendix A — defect register

| ID | Sev | File:line | One-line |
|---|---|---|---|
| W1/F1 | BLOCKER | `runtime/consensus_step.rs:1359-1361` | vote round = local round |
| W2/F2 | BLOCKER | `node/consensus_driver.rs:2248-2255` | rescue envelope = body's old signed round |
| W3/F3 | BLOCKER | `runtime/consensus_step.rs:1023-1027, 1071` | `count >= 2` unsatisfiable at N=3, one ahead |
| W4/F4 | HIGH | `consensus_net.rs:197-204`, `node/policy.rs:1058-1062` | send prune drops late votes/precommits |
| W5/F5 | HIGH | `runtime/consensus_step.rs:1269-1295, 1319-1324` | align to earliest proposer slot, not `block.round` |
| F6 | HIGH | `consensus_driver.rs:3179-3181` vs `consensus_step.rs:990-1082` | documented skip-while-armed rule does not exist |
| F6b | HIGH | `consensus/sortition.rs:955-956` | timeout plateaus at `base+10s`; no mean reversion |
| F7 | MED | `runtime/consensus_step.rs:1189-1191` + driver `:3013-3023` | proposal dropped on apply-in-flight |
| F8 | MED | `consensus/engine.rs:1598-1600` | live proposal can be un-votable (floor >= proposal round) |
| F9 | MED | `consensus/engine.rs:2713-2722, 2730-2742` | bodyful lock is unreleasable; a burned value round wedges the height |
| F10 | LOW | `consensus/engine.rs:2288-2297, 2353-2358` | sync jumps counted as nil rounds |
| F11 | DOC | `docs/PENTEST2_CONSENSUS.md:320-321`, `docs/CONSENSUS_SYNC.md:135`, `docs/REVIEW_CONSENSUS.md:333-343`, `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md` §2 | claims/citations stale |

## Appendix B — method and limits

* No source or test file was modified. No node was contacted. Nothing was executed against
  the live cluster.
* Every behavioural claim is traced to a cited line. Inferences are marked **[INFERRED]** and
  name the checks they rest on. No wall-clock numbers are claimed beyond the constants in
  the cited code (`3_000 ms` base, `10_000 ms` cap, `5_000 ms` adaptive cap).
* The "3 s per round" live figure is **not** reproduced by the frozen ladder at
  `r >= 3` (13 s); the discrepancy is itself evidence that the live round movement is
  peer-driven (`sync_round_to`) rather than timer-driven, which is consistent with F6 but was
  not measured here. Marked **[UNVERIFIED]** on the live side.
* Line numbers move; the citations are stable only for the tree named at the top.
