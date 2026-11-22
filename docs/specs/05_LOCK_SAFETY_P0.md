# P0 lock safety: local hardening and deployment constraints

> **Status:** Audit sections below record the pre-integration baseline. Sections
> **Resolution 1–3** at the bottom of this document specify the resolved BFT
> cross-kind rule, the `SafetyAuthority` signing/persistence/quarantine
> contract, and the implementation & test matrix for `SafetyRecordStore`
> integration.

## Rules

At one height a lock's round must never decrease. A prevote quorum for the
same value at an older round cannot replace a newer lock, including after
checkpoint restore. A conflicting value may be precommitted only when a
verified non-nil prevote quorum at a strictly higher round permits the normal
unlock. A local timeout, missing body, empty vote set, pruned votes, or failure
to observe a precommit certificate is not evidence that no certificate exists
elsewhere. Re-phase must preserve the lock regardless of body availability.
These rules intentionally prefer safety to recovery from a stall.

## Audit note and limitations

The local changes are not an end-to-end crash-safety or fork proof. The current
driver signs a late precommit before checking its precommit-specific broadcast
floor; a later prevote alone does not block an earlier precommit. Whether such
cross-kind ordering is safe requires protocol-level analysis; the existing
regression demonstrates signing, not a driver broadcast or a fork.

The vote watermark is persisted before broadcast but missing persistence and
read/write failures do not stop broadcast. Lock checkpoints and bodies are
queued asynchronously after broadcast, not atomically fsynced with the vote.
A crash can therefore lose the safety lock. A fail-closed, atomic durable
safety record and migration of existing records are separate deployment
blockers, including handling missing, corrupt, and legacy state. Do not infer
restart safety from this local patch.

The former timeout-only bodyless-unlock assertions in the deadlock breaker,
re-phase and nil-precommit tests conflict with this rule. They now require lock
preservation while retaining their forward-round, scan-window, no-QC and
idempotency checks; re-phase also tests deciding the locked value.

## Mixed versions

No wire format or quorum change is specified here. Wire compatibility does not
imply safety: older validators can still regress or drop locks, and a mixed
deployment has no established safety guarantee. A coordinated rollout and
audited migration/recovery procedure for durable safety records are required
before relying on the new rule. No activation mechanism or safe rolling-upgrade
protocol has been established; liveness can also degrade.

## Signing-path audit and integration blocker

The durable `SafetyRecordStore` is an isolated storage primitive, **not** a
signing authority. It stores an opaque payload; it does not enforce any
consensus transition, authorize initialization, or detect rollback or clones.
No production vote path currently reads or writes it.

The node driver calls `make_prevote` on catch-up, the normal proposal and
timeout paths, and the inbound-proposal fast path. It calls `make_precommit`
after processing inbound messages. Both reach `make_vote_at`, which creates
the shard-bound preimage and calls `sign_bytes` (local key or remote signer),
then may attach a Falcon signature. Only *after* this does the driver call
`persist_vote_watermark_before_broadcast`, update its in-memory floors, admit
its own vote, and enqueue it; cached votes can subsequently be retransmitted.
The precommit-specific floor is checked even later, after `make_precommit`.
The runtime's public vote methods are also called by the in-process cluster,
so a guard solely at the driver's outbox is not a universal signing guard.
Proposal signing has separate paths in `runtime/mev_sync.rs`; whether proposal
equivocation must be covered by the same authority must be resolved explicitly.

`make_precommit` invokes `try_prevote_quorum_at`, which can unlock on a newer
conflicting polka, then can install a lock before attempting the signature.
Other lock changes occur in `try_precommit_quorum` and startup restore. The
legacy watermark has only the last entry of each kind; read failures are
treated as empty and write/flush failures only logged. The lock checkpoint and
body are separately queued after the vote is enqueued/flushed. These are not a
single serialized, durable decision, and a failed signer can still leave an
in-memory lock transition. Startup also ignores watermark read errors.

### Late polka and cross-kind ordering

The existing policy allows a precommit at an older polka round after a later
prevote, because its floor is per-kind; the existing floor test demonstrates
that policy, not a quorum-intersection proof. For example, a validator can
prevote B at round 11 while unlocked, then receive an A polka at round 0 and
sign an A precommit at round 0. Its round-11 prevote was not constrained by
the subsequently acquired A lock. This is a safety-relevant execution to
analyze, not by itself a demonstrated fork: feasibility of conflicting
certificates depends on the full validator set, weighted quorums, message
history, and other validators' rules. A per-kind no-double-sign check alone
does not establish the lock invariant. Conversely, replacing it with a union
floor changes late-polka behavior and may reintroduce stalls; neither policy is
approved here without a protocol proof, regression/simulation coverage and
activation analysis.

### Driver extraction: equivalence boundaries

The private driver loop is not exercised by the existing late-polka signer
regression. The precommit call can mutate the lock and sign before the driver
checks its per-kind floor. On admission the driver attempts watermark
persistence, updates both floors, admits its own vote, enqueues and flushes,
then updates its cached vote and queues the lock checkpoint. Persistence
errors do not abort this sequence. A differential fixture must observe these
effects and their order, including signer failure and admission failure, rather
than only comparing the guard's Boolean result.

The flush operates on the shared outbox, not only the new precommit. In the
current source it prunes same-height votes at least two rounds behind the local
round, so the round-4 precommit in the round-11 example is signed and may be
enqueued but is removed before sender enqueue. Moreover, `flush_outbox` drains
a chunk before `ConsensusSender::enqueue`; when enqueue returns false, that
chunk is not restored despite the comments describing retention. These are
source observations, not an executed driver integration test. A refactor must
not silently change either behavior under the guise of equivalence; any
correction needs its own review and tests.

Cached votes are re-enqueued independently by the periodic retransmission
path, and other events flush the same outbox. Testing a newly extracted
precommit helper alone cannot establish coverage of those paths. The current
loop constructs its concrete network and sender internally and also loads
Falcon keys during startup; a no-live-network baseline therefore needs
carefully scoped test instrumentation or a separately reviewed seam. Until
the unchanged driver and the candidate are both observable under the same
valid and failure scenarios, no equivalence or complete-path claim is made.

### Required authority and migration contract (not implemented)

Before enabling signing, one serialized authority must own the current
validated safety state for each validator, chain and shard, across every
production signing entry point and every process using that key. Its state
must include the applicable height, lock/value identity and round, enough
exact vote history or conservative floors for the approved cross-kind policy,
and sufficient verified finality/transition evidence to advance heights
without losing prior safety constraints. It must determine the vote and lock
transition from validated evidence, durably write the complete next state
before invoking either local or remote signing, and prevent enqueue and
retransmission on an indeterminate write/flush result. All lock mutation,
finalization, catch-up and restore paths must reconcile with the same
authority; stale, corrupt, missing, mismatched or rollback-suspect state must
not silently become an empty state. Failed signing after a successful durable
reservation must not release the reservation. A remote signer or another
process independently using the key can bypass a node-local store; exclusive
key custody or signer-enforced fencing is necessary.

An absent store is ambiguous, including on a seemingly fresh data directory:
it cannot prove that a validator key has never signed elsewhere. Legacy
watermarks and asynchronous checkpoints can each lag a signature or lock and
cannot automatically establish a safe starting state. Migration therefore
requires quarantine, exclusive custody/fencing of all old signers and copies,
and an audited recovery procedure backed by adequate independent evidence or
an explicitly safe key/validator replacement and chain activation plan. Do
not manufacture a fresh record from legacy state alone. Missing/corrupt data,
failed flush, ambiguous remote-signing results, restored backups and duplicate
deployments must remain fail-closed until resolved by that procedure.

Acceptance requires integration tests exercising every signing and
retransmission route, crash points before/after durable reservation and
signing, injected insert/flush failures with no signature or outbound vote,
restart/lock restoration, legacy and missing-state quarantine, concurrent
and stale writers, and both late-polka orderings. The protocol decision and
its quorum proof, mixed-version and chain-wide activation analysis, audit
note, and full consensus gate remain prerequisites. This document records
requirements and unresolved choices; it does not activate a new rule.

---

## Resolution 1: Cross-kind ordering protocol analysis and transition matrix

### 1.1 Exact code behavior today

1. **`HeightConsensus::try_prevote_quorum_at` (`stellereum/src/consensus/engine.rs:2101-2182`)**:
   - Scans `rounds_to_inspect()` newest-first and merges with `self.observed_polka` (`engine.rs:2148-2152`, written eagerly by `add_prevote -> note_polka` at `engine.rs:1871, 2243-2266`).
   - Only a **non-nil** polka (`Some((polka_round, other_block))`) with `polka_round > locked_round && !self.same_value(other_block, locked_block)` unlocks `self.locked = None` (`engine.rs:2171-2180`). A nil quorum never unlocks (`engine.rs:2166-2170`).
2. **`ValidatorRuntime::make_precommit` (`stellereum/src/runtime/consensus_step.rs:1621-1679`)**:
   - Calls `self.hc.try_prevote_quorum_at()`, then `self.hc.best_polka()` (`engine.rs:2280-2287`).
   - Checks `if !self.hc.same_value(locked_block, target) && qc_round <= locked_round { return None; }` (`consensus_step.rs:1665-1672`).
   - **Defect 1 (premature in-memory lock + missing body check):** Sets `self.hc.locked = Some((target, qc_round))` (`consensus_step.rs:1675-1677`) **without** requiring `self.blocks.contains_key(&target)` / `value_id_of(&target).is_some()` and **before** `make_vote_at` calls `sign_bytes` (`consensus_step.rs:1496`).
   - **Defect 2 (sign before floor/persist):** `make_vote_at` (`consensus_step.rs:1478-1517`) invokes `sign_bytes(&msg)` and `falcon_signing_key().sign(&msg)` **before** `consensus_driver.rs:3722-3727` checks `last_precommitted` / `precommit_floor` or calls `persist_vote_watermark_before_broadcast`.
3. **`node/consensus_driver.rs` per-kind floors (`consensus_driver.rs:1214-1230, 2530, 2624, 3227, 3722-3727`)**:
   - `vote_floor` tracks `max(prevote.round, precommit.round)` and gates `prevote` (`consensus_driver.rs:1908, 2530, 2624, 3227`).
   - `precommit_floor` tracks **only** `precommit` rounds (`consensus_driver.rs:1227-1230, 3723`), justified by `vote_watermark_tests::late_polka_precommit_ignores_the_prevote_floor` (`consensus_driver.rs:5288-5304`).
   - **Defect 3 (lossy watermark history):** `VoteWatermark::note` (`storage.rs:2640-2645`) overwrites `self.prevote` in place, so a later `nil` prevote erases an earlier non-nil prevote at the same height.
   - **Defect 4 (outbox pruning discrepancy):** `flush_outbox` (`node/policy.rs:1037`, `consensus_net.rs:198-201`) drops any outbound vote with `vote.round + SUPERSEDED_ROUND_LAG <= hc.round` (`SUPERSEDED_ROUND_LAG = 2`). When `hc.round = 11` and `v.round = 0`, `consensus_driver.rs:3737` signs, persists, and enqueues `v`, then `flush_outbox` silently drops `v` before `ConsensusSender::enqueue` (`05_LOCK_SAFETY_P0.md:100-108`). `tests/support/live_stand.rs` has no such outbox prune, which is why `masterchain_liveness_tests::a_late_polka_is_still_precommitted` (`masterchain_liveness_tests.rs:134, 158`) transmits the late precommit while the production driver would prune it.

### 1.2 Proof: unrestricted retroactive `precommit(r_polka, X)` after `prevote(r_later, Y)` violates BFT safety

**Claim:** Allowing a validator $v$ to sign `precommit(r_polka, X)` ($X \neq \mathrm{nil}$) after $v$ has already signed a conflicting non-nil `prevote(r_later, Y)` ($r_{\text{later}} > r_{\text{polka}}$, $\mathrm{value\_id}(Y) \neq \mathrm{value\_id}(X)$) **breaks BFT agreement even with 4 honest validators ($f = 0$ Byzantine faults)** and even under the live-stand weighted quorum `[1500, 1000, 1000, 1000]` (total `4500`, quorum `3001`).

**Counterexample (4 honest validators $\{A, B, C, D\}$, equal `[1,1,1,1]` quorum `3`, or weighted `[1500,1000,1000,1000]` quorum `3001` with $A=1500$):**

1. **Round 0 ($r_0$):** Proposer $A$ proposes $X$. Validators $A, B, C$ (power `3` or `3500` $\ge$ quorum) are unlocked and each sign `prevote(r_0, X)`. Their `r_0` prevotes are delayed in transit.
2. **Round 11 ($r_{11} > r_0$):** Before the delayed `r_0` prevotes arrive, $A, B$ (or $B, C$ in equal-power) and $D$ time out to $r_{11}$ while **still `locked = None`**. Proposer $D$ proposes $Y$ ($\mathrm{value\_id}(Y) \neq \mathrm{value\_id}(X)$). Because $A, B, D$ (or $B, C, D$) are unlocked:
   - $A, B, D$ (weighted `3500 >= 3001`) or $B, C, D$ (equal `3 >= 3`) each sign **`prevote(r_{11}, Y)`** (non-nil).
   - $D$'s `prevote(r_{11}, Y)` is delayed; $A, B$ have not yet observed the `r_{11}` polka.
3. **Late `r_0` polka arrives at $A, B, C$:** All `prevote(r_0, X)` from $\{A, B, C\}$ arrive.
   - Under the unrestricted per-kind `precommit_floor` rule, $A, B, C$ have `precommit_floor = None`, so all three acquire lock $(X, r_0)$ retroactively and sign `precommit(r_0, X)`.
   - $C$ receives `{A, B, C}` `precommit(r_0, X)` (`3500 >= 3001` / `3 >= 3`) and **FINALIZES $X$ at height $H$**.
4. **Delayed `prevote(r_{11}, Y)` from $D$ arrives at $A, B$ (or $B, C$):**
   - $A$ and $B$ observe polka $(r_{11}, Y)$ with `polka_round = 11 > locked_round = 0` and `!same_value(Y, X)`.
   - `try_prevote_quorum_at()` (`engine.rs:2177-2179`) **legally unlocks** $(X, r_0)$ on $A$ and $B$.
   - $A, B, D$ sign `precommit(r_{11}, Y)`, form a valid `Precommit QC` for $Y$ at $r_{11}$, and **FINALIZE $Y \neq X$ at height $H$**.

**Result:** Two honest validators finalize conflicting blocks $X \neq Y$ at height $H$ with **zero equivocation** (every vote cast by $A, B, C, D$ has a distinct `(height, round, kind)`). The failure is identical if `A` or `C` was **locked** on some $L$ at $r_{11}$ and prevoted $(r_{11}, L)$ (`L != X`), then tried to precommit $(r_0, X)$ with $r_0 > r_{\text{lock}}$: `prevote(r_{11}, L)` still contributes quorum power to $L$ at $r_{11} > r_0$ and can unlock $(X, r_0)$.

### 1.3 Soundness proof of the exact cross-kind condition

**Theorem (Safe Retroactive Precommit Condition):**
Assume quorum intersection: for any two quorums $Q_1, Q_2$ at height $H$, $\mathrm{power}(Q_1) + \mathrm{power}(Q_2) - \mathrm{total\_power} > \mathrm{byzantine\_power}$, so every pair of quorums shares at least one honest validator.

Suppose every honest validator obeys the following four invariants before signing any vote at height $H$:
- **(I1) Prevote floor:** Never sign any `prevote(r, *)` with $r \le \text{highest\_prevote\_round}$.
- **(I2) Precommit floor:** Never sign any `precommit(r, *)` with $r \le \text{highest\_precommit\_round}$.
- **(I3) Lock-respecting prevote:** When holding lock $(L, r_{\text{lock}})$, never sign `prevote(r, Y)` ($Y \neq \mathrm{nil}$) with $\mathrm{value\_id}(Y) \neq \mathrm{value\_id}(L)$ unless first unlocked by a verified non-nil polka $(r_u, Z)$ with $r_u > r_{\text{lock}}$ and $\mathrm{value\_id}(Z) \neq \mathrm{value\_id}(L)$.
- **(I4) Non-conflicting cross-kind precommit:** Sign `precommit(r_polka, X)` ($X \neq \mathrm{nil}$) **only if**:
  1. $r_{\text{polka}} > \text{highest\_precommit\_round}$ (from I2);
  2. There exists a verified non-nil prevote QC for $(r_{\text{polka}}, X)$ and full validated body $X$;
  3. If locked on $(L, r_{\text{lock}})$, either $\mathrm{value\_id}(X) = \mathrm{value\_id}(L)$ or $r_{\text{polka}} > r_{\text{lock}}$;
  4. **Cross-kind guard:** For **every** prevote previously signed by this validator at any round $r' > r_{\text{polka}}$ at height $H$, either its target was `nil`, OR $\mathrm{value\_id}(\text{target}) = \mathrm{value\_id}(X)$;
  5. Lock $(X, r_{\text{polka}})$ (if `r_polka > r_lock` or unlocked) and the updated floors are durably flushed **before** signing `precommit(r_polka, X)`.

**Proof by strong induction on round $r > r_0$:**
Suppose $X$ is decided (committed) at round $r_0$ via `Prevote QC(r_0, X)` and `Precommit QC(r_0, X)` ($Q_{\text{pre}}$).
1. *Base ($r = r_0$):* Every honest validator in $Q_{\text{pre}}$ observed `Prevote QC(r_0, X)`; by quorum intersection at $r_0$, no conflicting `Prevote QC(r_0, Y)` ($\mathrm{value\_id}(Y) \neq \mathrm{value\_id}(X)$) can form at $r_0$.
2. *Inductive step ($r > r_0$):* Assume no polka for any $Y$ with $\mathrm{value\_id}(Y) \neq \mathrm{value\_id}(X)$ exists at any round $r'' \in (r_0, r)$. Consider any honest validator $h \in Q_{\text{pre}}(r_0, X)$.
   - Case A: $h$ signs `prevote(r, *)` **after** signing `precommit(r_0, X)`. By (I4.5), $h$ already holds lock on $X$ at round $\ge r_0$. By the inductive hypothesis, no polka at $r'' \in (r_0, r)$ unlocked $h$. By (I3), $h$ can only prevote $X$ (same `value_id`) or `nil` in round $r$.
   - Case B: $h$ signed `prevote(r, *)` **before** signing `precommit(r_0, X)`. Since $r > r_0$, (I4.4) guarantees $h$'s signed `prevote(r, *)` was either `nil` or had $\mathrm{value\_id} = \mathrm{value\_id}(X)$, and by (I1) $h$ cannot sign another prevote in round $r$.
   Thus no honest validator $h \in Q_{\text{pre}}(r_0, X)$ ever casts `prevote(r, Y)` with $\mathrm{value\_id}(Y) \neq \mathrm{value\_id}(X)$. By quorum intersection, no polka for $Y$ can form at round $r$, completing the induction. $\blacksquare$

### 1.4 Exact Transition Matrix for `precommit(r_polka, X)` after `prevote(r_later, T)` ($r_{\text{later}} > r_{\text{polka}}$)

In all rows below, preconditions `r_polka > highest_precommit_round`, verified `Prevote QC(r_polka, X)`, and local body availability for $X$ are required. "Latest" vs "All" matters: **every** signed prevote at $r' > r_{\text{polka}}$ must satisfy the row (not only the most recent prevote!).

| Prevote(s) signed at $r' > r_{\text{polka}}$ | Lock state at $r_{\text{later}}$ | Target relation / lock comparison | Allowed? | Resulting `locked` / rationale |
|---|---|---|---|---|
| **Only `nil`** (`T == None` for all $r' > r_{\text{polka}}$) | **Unlocked** (`None`) | Any valid $X$ | **ALLOW** | Lock becomes `(X, r_polka)`. `nil` adds 0 power to any conflicting polka at $r'$. |
| **Only `nil`** (`T == None` for all $r' > r_{\text{polka}}$) | **Locked** `(L, r_lock)` | $\mathrm{value\_id}(X) = \mathrm{value\_id}(L)$ | **ALLOW** | Keep `(L, r_lock)` if `r_lock >= r_polka`, else `(X, r_polka)` (monotonic). |
| **Only `nil`** (`T == None` for all $r' > r_{\text{polka}}$) | **Locked** `(L, r_lock)` | $\mathrm{value\_id}(X) \neq \mathrm{value\_id}(L)$ and `r_polka > r_lock` | **ALLOW** | Higher polka unlocks `L` and installs `(X, r_polka)`. |
| **Only `nil`** (`T == None` for all $r' > r_{\text{polka}}$) | **Locked** `(L, r_lock)` | $\mathrm{value\_id}(X) \neq \mathrm{value\_id}(L)$ and `r_polka <= r_lock` | **FORBID** | Violates existing lock `(L, r_lock)` (`consensus_step.rs:1669`). |
| **Non-nil same value** ($\mathrm{value\_id}(T) = \mathrm{value\_id}(X)$ for all non-nil $r' > r_{\text{polka}}$) | **Unlocked** or **Locked** on `X` | $\mathrm{value\_id}(X) = \mathrm{value\_id}(L)$ (or `None`) | **ALLOW** | Voting same `value_id` at $r' > r_{\text{polka}}$ cannot certify a conflicting value $Y \neq X$. Keep `max(r_lock, r_polka)` lock round. |
| **Non-nil same value** ($\mathrm{value\_id}(T) = \mathrm{value\_id}(X)$) | **Locked** `(L, r_lock)`, $L \neq X$ | (`r_polka > r_lock`) | **ALLOW** (rare: unlocked on intermediate polka for $X$) | Still requires `r_polka > r_lock` and no non-nil `L` prevote in $(r_{\text{polka}}, r_{\max}]$. |
| **Any conflicting non-nil** ($\exists r' > r_{\text{polka}}$ with $T \neq \mathrm{nil}$ and $\mathrm{value\_id}(T) \neq \mathrm{value\_id}(X)$) | **Unlocked** at $r'$ | $\mathrm{value\_id}(T) \neq \mathrm{value\_id}(X)$ | **FORBID** | **4-validator fork (§1.2):** $T$ at $r'$ can form a polka that unlocks $(X, r_{\text{polka}})$ and commits $T \neq X$. |
| **Any conflicting non-nil** ($\exists r' > r_{\text{polka}}$ with $T \neq \mathrm{nil}$ and $\mathrm{value\_id}(T) \neq \mathrm{value\_id}(X)$) | **Locked** `(L, r_lock)` at $r'$ | $\mathrm{value\_id}(T) \neq \mathrm{value\_id}(X)$ (e.g. $T = L$) | **FORBID** | Same fork: `prevote(r', L)` can form polka for $L$ at $r' > r_{\text{polka}}$ and unlock $(X, r_{\text{polka}})$. |

### 1.5 Exact $O(1)$ representation of all prior prevotes (closing the `VoteWatermark` overwrite hole)

Storing only the single latest `prevote` (`storage.rs:2640-2645`) is **unsound**: if a node prevotes $(r_{11}, Y)$ (non-nil) and then prevotes $(r_{12}, \mathrm{nil})$, overwriting `(11, Y)` with `(12, None)` would falsely make a late polka $(r_0, X)$ look safe.

Because (I1) guarantees non-nil prevote rounds at one height are strictly increasing, the entire prevote conflict predicate over all rounds $r' > r_{\text{polka}}$ is represented **without loss** in $O(1)$ fixed space by three fields:
- `highest_prevote_round: Option<u32>` — highest round of **any** signed prevote (`nil` or non-nil);
- `last_non_nil_prevote: Option<(u32, BlockHash, [u8; 32])>` — `(round, block_hash, value_id)` of the highest-round non-nil prevote signed at this height;
- `prev_other_non_nil_prevote_round: Option<u32>` — highest round of any signed non-nil prevote whose `value_id != last_non_nil_prevote.value_id`.

**Update on signing non-nil `prevote(r, bh, vid)`** (with `r > highest_prevote_round`):
```text
match last_non_nil_prevote:
  None => last_non_nil_prevote = Some((r, bh, vid))
  Some((r_last, _, v_last)) if v_last == vid =>
      last_non_nil_prevote = Some((r, bh, vid))   // prev_other unchanged
  Some((r_last, _, _)) =>
      prev_other_non_nil_prevote_round = Some(prev_other_non_nil_prevote_round.map_or(r_last, |p| p.max(r_last)))
      last_non_nil_prevote = Some((r, bh, vid))
```
**Check on `precommit(r_polka, X, vid_x)`:**
- Allowed iff:
  - `last_non_nil_prevote` is `None`, OR `r_polka >= r_last`, OR (`v_last == vid_x && prev_other_non_nil_prevote_round.is_none_or(|p| r_polka >= p)`).
  - Otherwise **REFUSE** (there exists a signed non-nil prevote at $r' > r_{\text{polka}}$ with `value_id != vid_x`).

*(Note: The ultra-conservative alternative — a single `highest_signed_round` shared across prevotes and precommits — also satisfies safety trivially, at the cost of forbidding `precommit(r_0, X)` even after `prevote(r_{11}, nil)`. That breaks `late_polka_precommit_ignores_the_prevote_floor` (`consensus_driver.rs:5288`) and causes `a_late_polka_is_still_precommitted` (`masterchain_liveness_tests.rs:134, 158`) to require a new `validRound`/polka-carrying proposal wire change. The `(last_non_nil_prevote, prev_other_non_nil_prevote_round)` rule above is therefore the approved policy: it is proven safe AND preserves late-polka precommits after `nil` or same-value prevotes.)*

### 1.6 Liveness impact on `a_late_polka_is_still_precommitted` & required driver/runtime fixes

1. **In `masterchain_liveness_tests::a_late_polka_is_still_precommitted` / `..._four_validators` (`masterchain_liveness_tests.rs:134, 158`):**
   - Node 0 (`1500` STELL, `vote_delay(40_000)`) prevotes $B_0$ at $r_0$, then races ahead while deaf to inbound votes. Whenever Node 0 is scheduled proposer while unlocked (`live_stand.rs:525`, `ts = height * 1000 + round`), Node 0 proposes a fresh block $B_k \neq B_0$ and prevotes $(r_k, B_k)$ (non-nil conflicting).
   - Under the safe cross-kind rule (§1.4), once Node 0 signed `prevote(r_k, B_k)` ($B_k \neq B_0$), Node 0 **must refuse** to sign `precommit(r_0, B_0)` when the $r_0$ polka arrives at `t = 40s`.
   - **Liveness recovery without weakening safety:** When Node 0 observes a valid late polka $(r_{\text{polka}}, B_0)$ in `make_precommit` / `add_prevote` (with body $B_0$ present and `r_polka > r_lock` or `locked == None`), even when the cross-kind guard forbids signing `precommit(r_polka, B_0)` for `r_polka`, Node 0 **still adopts lock `(B_0, r_polka)`** (persisted durably: `put_block` + `flush`, then `SafetyRecordStore::persist` — safe because locking only *restricts* future prevotes at $r > r_k$ and never emits a precommit for `r_polka`). Thereafter, Node 0 stops proposing conflicting fresh blocks $B_{k+1} \neq B_0$: on subsequent rounds it proposes/prevotes only re-stamped $B_0$ (same `value_id`) or `nil`, so when the next re-stamped polka $(r_{\text{next}}, B_0)$ arrives, **every** prevote in $(r_{\text{next}}, r_{\text{cur}}]$ is `nil` or same-value $B_0$, allowing Node 0 to precommit $(r_{\text{next}}, B_0)$ and finalize!
2. **In `node/consensus_driver.rs` / `node/policy.rs` (`outbox` pruning):**
   - `flush_outbox` (`node/policy.rs:1037`, `consensus_net.rs:198`) currently prunes any vote with `vote.round + SUPERSEDED_ROUND_LAG <= hc.round`.
   - When the driver casts a valid late-polka `Precommit` at `v.round < rt.hc.round`, `flush_outbox` must **not** prune that `Precommit` on `SUPERSEDED_ROUND_LAG` (only `Prevote`s and `Proposal`s, or precommits strictly below `observed_polka.round`, may be pruned as superseded). Otherwise a valid `make_precommit` vote is persisted locally and never hits the wire.

---

## Resolution 2: `SafetyAuthority` contract, durable payload, lock ordering, and legacy quarantine

### 2.1 Single serialized authority and choke-point interface

`SafetyRecordStore` (`stellereum/src/storage.rs:151-254`) remains the low-level sled CAS primitive. Above it, introduce `SafetyAuthority` (new module `stellereum/src/safety.rs`, re-exported via `stellereum/src/lib.rs`) owned by `ValidatorRuntime` (`stellereum/src/runtime/mod.rs:311`):

```rust
pub struct SafetyAuthority {
    inner: std::sync::Mutex<SafetyAuthorityState>,
}
```

**Choke-point sealing rules (`runtime/consensus_step.rs`, `runtime/anchors.rs`, `runtime/mev_sync.rs`, `runtime/mod.rs`):**

1. **Remove unguarded vote/proposal signing:**
   - `ValidatorRuntime::sign_bytes` (`runtime/anchors.rs:3091`) must be `#[cfg(test)]`-only or private to `SafetyAuthority` callbacks; production runtime methods (`make_vote`, `make_vote_at`, `make_prevote`, `make_precommit`, `propose`, `restamp_for_round`) must **never** call `self.key.sign`, `self.remote_signer.sign`, or `fk.sign` directly.
   - `make_vote` (`consensus_step.rs:1470`) and `make_vote_at` (`consensus_step.rs:1478`) are **replaced/sealed** behind `SafetyAuthority::authorize_and_sign_vote(...)`: the **only** code path that invokes `sign_bytes` + `falcon_signing_key().sign` for a `Vote` receives a private/sealed capability inside `SafetyAuthority` **after** `SafetyRecordStore::persist` (`+ db.flush()`) has returned `Ok`.
   - `make_prevote(&self)` (`consensus_step.rs:1547`) keeps `&self` compatibility if needed via `self.safety.inner.lock()` (serializing concurrent callers), or becomes `&mut self`; either way it delegates 100% of floor/lock validation, durable persistence, and signing to `SafetyAuthority`.
   - `make_precommit(&mut self)` (`consensus_step.rs:1621`) delegates 100% of body lookup, lock transition, `put_block` + `flush`, `SafetyRecordStore::persist`, signing, and `hc.locked` update to `SafetyAuthority`.
2. **Proposal signing (`runtime/mev_sync.rs:901-917, 2203-2347`):**
   - Move `propose` signing (`mev_sync.rs:2203`) **after** the pre-gossip `MAX_CONSENSUS_MSG` size check/trimming (`mev_sync.rs:2224-2347`, estimating wire size with deterministic placeholder signature lengths before signing once) so a block is signed at most once per `(height, round)`.
   - Both `propose` and `restamp_for_round` sign exclusively through `SafetyAuthority::authorize_and_sign_proposal(...)`, which checks & persists `highest_proposed` before invoking `sign_bytes` + `fk.sign`, eliminating `SLASH-B` equivocation across crashes.
3. **Production vs in-process test backend:**
   - `SafetyBackend::Durable { store: SafetyRecordStore, storage: Arc<Storage> }` — **the only backend permitted in `node/consensus_driver.rs` / `node/bootstrap.rs`**. If `persistence` is `None` for a validator in production, `SafetyAuthority` starts in `Mode::Quarantined` (fail-closed Observer).
   - `SafetyBackend::Ephemeral(InMemorySafetyRecord)` — available **only** for `ValidatorRuntime::new(...)` in-process unit tests / `runtime/cluster.rs` / `tests/support/live_stand.rs` (running the exact same `SafetyRecordPayload` canonical codec, generation CAS, cross-kind rules, and lock ordering in memory; `consensus_driver.rs` never constructs `Ephemeral`).
4. **Driver-level redundancy (`node/consensus_driver.rs`):**
   - Driver-local `vote_floor` / `precommit_floor` / `last_prevoted` / `last_precommitted` become **liveness dedup / fast-skip hints only** (never the safety boundary).
   - Remove silent-failure `persist_vote_watermark_before_broadcast` (`consensus_driver.rs:61-95`) from the post-sign path; durability happens **inside** `SafetyAuthority` **before** `sign_bytes`.
   - Legacy `vote_watermark` and `ConsensusCheckpoint` may still be read during boot reconciliation (§2.4), or retired after migration, but must never override or weaken `SafetyRecordStore`.

**Core `SafetyAuthority` API:**

```rust
pub enum AuthorityMode {
    Active,
    ObserverOnly,              // configured non-validator (STELL_OBSERVER=1 / !is_validator)
    Quarantined(String),       // fail-closed: corrupt/missing/legacy/IO failure; never signs
}

pub trait VoteSigner {
    fn sign_ed25519(&self, msg: &[u8]) -> Option<Vec<u8>>;
    fn sign_falcon(&self, msg: &[u8]) -> Option<(ValidatorId, Vec<u8>)>;
}

impl SafetyAuthority {
    pub fn open_from_storage(
        storage: Arc<Storage>,
        identity: SafetyRecordIdentity,
        boot_ctx: SafetyBootContext,
    ) -> Self; // NEVER panics into Active; any ambiguity -> Quarantined

    pub fn mode(&self) -> AuthorityMode;
    pub fn can_sign(&self) -> bool; // true iff AuthorityMode::Active
    pub fn current_state(&self) -> Option<SafetyRecordPayload>;

    pub fn authorize_and_sign_prevote(
        &self,
        height: Height,
        round: Round,
        shard_id: ShardId,
        target: Option<(BlockHash, [u8; 32] /* value_id */)>,
        signer: &dyn VoteSigner,
    ) -> Result<Vote, SafetyRefusal>;

    pub fn authorize_and_sign_precommit(
        &self,
        height: Height,
        polka_round: Round,
        shard_id: ShardId,
        polka_block: &Block,
        prevote_qc: &QuorumCertificate,
        validators: &ValidatorSet,
        committee_schedule: CommitteeSchedule,
        signer: &dyn VoteSigner,
    ) -> Result<(Vote, Option<SafetyLockRecord>), SafetyRefusal>;

    /// Used when a higher conflicting polka justifies unlocking without emitting
    /// a precommit (or during liveness lock-adoption when cross-kind forbids precommit).
    pub fn record_polka_lock_transition(
        &self,
        height: Height,
        polka_round: Round,
        polka_block: &Block,
        prevote_qc: &QuorumCertificate,
        validators: &ValidatorSet,
        committee_schedule: CommitteeSchedule,
    ) -> Result<Option<SafetyLockRecord>, SafetyRefusal>;

    pub fn authorize_and_sign_proposal(
        &self,
        height: Height,
        round: Round,
        block_hash: BlockHash,
        signer: &dyn VoteSigner,
    ) -> Result<(Vec<u8>, Option<(ValidatorId, Vec<u8>)>), SafetyRefusal>;

    pub fn advance_height(
        &self,
        new_height: Height,
        finalized_height: Height,
        finalized_hash: BlockHash,
    ) -> Result<(), SafetyRefusal>;
}
```

### 2.2 Exact `SafetyRecordStore` identity and payload schema

**1. `SafetyRecordIdentity` derivation (`storage.rs:54-58`):**
- `validator`: `self_vote_id` (`[u8; 32]`, Ed25519 pubkey of validator; matches `remote_signer.public_key()` when remote signer is active).
- `shard`: `block_shard` (`u32`, `0` for masterchain, `1..N` for workchains).
- `chain`: deterministic 32-byte commitment derived at boot from `(consensus_chain_id(), genesis_state_root)`:
  `BLAKE3(b"STELL_SAFETY_CHAIN_V1" || consensus_chain_id().to_be_bytes() || genesis_state_root)`
  (where `genesis_state_root` is the persisted/verified root from `node/bootstrap.rs:1133-1178, 293-317`). This binds the record to both the numeric chain ID and the exact genesis state.

**2. `SafetyRecordPayload` schema (stored inside `SafetyRecord::payload`, outer `SafetyRecord` v1 envelope at `storage.rs:70-128`):**

Canonical fixed-order big-endian encoding (`encode_canonical` / `decode_canonical`, strict exact-length check — trailing bytes or unknown tags/versions return `Err` and quarantine):

| Field | Wire Type | Meaning & Invariant |
|---|---|---|
| `schema_version` | `u16` (BE) | Must equal `1`. Any other value fails closed (`Quarantined`). |
| `height` | `u64` (BE) | Active consensus height (`>= 1`). Always `finalized_height + 1` after advance/snapshot. |
| `finalized_height` | `u64` (BE) | Monotonic finalized tip height (`0` at genesis). Never decreases. |
| `finalized_hash` | `[u8; 32]` | Finalized block hash at `finalized_height` (`[0; 32]` at height 0). |
| `highest_prevote_round` | `u8` tag + (`u32` if `1`) | Highest round for which any prevote (`nil` or value) was reserved at `height`. |
| `highest_precommit_round` | `u8` tag + (`u32` if `1`) | Highest round for which any precommit was reserved at `height`. |
| `last_non_nil_prevote` | `u8` tag + (`u32 \|\| [u8;32] \|\| [u8;32]` if `1`) | `(round, block_hash, value_id)` of highest-round non-nil prevote at `height`. |
| `prev_other_non_nil_prevote_round` | `u8` tag + (`u32` if `1`) | Highest round of any non-nil prevote at `height` with `value_id != last_non_nil_prevote.value_id`. |
| `locked` | `u8` tag + (`u32 \|\| [u8;32] \|\| [u8;32]` if `1`) | `(round, block_hash, value_id)` of current safety lock. Stores **both** signed `block_hash` (key in `storage.blocks`) and round-free `value_id` (`Block::value_id()`). |
| `highest_proposed` | `u8` tag + (`u32 \|\| [u8;32]` if `1`) | `(round, block_hash)` of last reserved proposal at `height`. |

*(Total encoded size: 78 bytes when all `Option`s are `None`, up to 227 bytes when all are `Some` — bounded, $O(1)$, deterministic, zero `serde(default)` ambiguity.)*

### 2.3 Exact execution order on taking a lock, voting, proposing, and advancing height

**Lock + Precommit sequence (`make_precommit` -> `authorize_and_sign_precommit`):**
1. **Evidence & body check:** Verify `prevote_qc` (`kind == Prevote`, `height == hc.height`, `round == polka_round`, `block_hash == Some(target)`, quorum power valid under `validator_set_for_height(height)` + `committee_schedule_at(height)`). Require `polka_block` in `self.blocks` with `polka_block.height == height` and `polka_block.compute_hash() == target`; compute `value_id = polka_block.value_id()`. If body is missing -> return `None` (no hash-only lock, no sign).
2. **Acquire `SafetyAuthority` mutex & validate transition:**
   - Require `AuthorityMode::Active` and `state.height == height`.
   - Require `state.highest_precommit_round.is_none_or(|r| polka_round > r)`.
   - Lock check against `state.locked`: if `Some(l)` with `l.value_id != value_id`, require `polka_round > l.round`.
   - Cross-kind check (§1.5): require no conflicting non-nil prevote at any $r' > \text{polka\_round}$.
   - Compute `next_locked`: if `state.locked.is_none_or(|l| polka_round > l.round)` -> `Some(SafetyLockRecord { round: polka_round, block_hash: target, value_id })`, else keep `state.locked`.
3. **Step A — Durable lock body BEFORE `SafetyRecordStore::persist`:**
   - If `next_locked` changed (new lock or higher lock round for `target`), call `storage.put_block(polka_block)` followed synchronously by `storage.flush()`.
   - If `put_block` or `flush` fails: **abort immediately** (`Err`), do **not** call `SafetyRecordStore::persist`, do **not** mutate `hc.locked`, do **not** call `sign_bytes`. (A crash after Step A but before Step B leaves an unreferenced block body in `blocks`, which is harmless.)
4. **Step B — Atomic durable safety reservation BEFORE `sign_bytes`:**
   - Build `next_state` with `highest_precommit_round = Some(polka_round)` and `locked = next_locked`.
   - Call `safety_store.persist(Some(expected_gen), next_state.encode_canonical()?)` (which performs generation CAS + `tree.insert` + `db.flush()`).
   - If `persist` fails (I/O, flush, generation mismatch, decode): transition `SafetyAuthority` to `Quarantined` (fail-closed Observer), **abort** without calling `sign_bytes`, without mutating `hc.locked`, and without adding to `outbox`.
   - Advance cached `(expected_gen, state)` to the persisted `SafetyRecord`.
5. **Step C — Cryptographic signing (`sign_bytes` + Falcon):**
   - Build `msg = vote_sign_bytes_for_shard(shard_id, height, polka_round, VoteKind::Precommit, &Some(target))`.
   - Call `signer.sign_ed25519(&msg)` (`sign_bytes`) and `signer.sign_falcon(&msg)`.
   - **Failed signer rule:** If signing returns `None` (e.g. remote signer unreachable/timeout), **never roll back** `SafetyRecordStore` or release the reservation (`highest_precommit_round` and `locked` stay durably persisted because the remote signer outcome may be ambiguous). Sync `hc.locked` in memory to `next_locked` and return `Err(SignerFailed)`.
6. **Step D — In-memory commit + outbox:**
   - Commit `self.hc.locked = next_locked.map(|l| (l.block_hash, l.round))`, `self.hc.note_value_id(target, value_id)`, admit own vote via `self.on_precommit(vote.clone())`, update driver bookkeeping (`cast_precommit`, `last_precommitted`, `precommit_floor`), and enqueue to `outbox` (exempting valid late-polka `Precommit` from `SUPERSEDED_ROUND_LAG` pruning in `flush_outbox`).

**Prevote sequence (`make_prevote` -> `authorize_and_sign_prevote`):**
1. Check `AuthorityMode::Active`, `state.height == height`, `round > state.highest_prevote_round`.
2. If `target == Some((bh, vid))`: verify against authoritative `state.locked` — if `Some(l)` then require `l.value_id == vid` (no in-memory `hc.locked = None` may bypass `state.locked`; any unlock must first go through `record_polka_lock_transition` with a verified `prevote_qc`).
3. Update `highest_prevote_round = Some(round)` and, if non-nil, `(last_non_nil_prevote, prev_other_non_nil_prevote_round)` (§1.5).
4. `safety_store.persist(Some(gen), ...)` (`+ db.flush()`). Error -> `Quarantined`, no `sign_bytes`.
5. `sign_bytes` + Falcon sign. Signer failure -> keep reservation, return `None`.
6. Return `Vote`, admit via `on_prevote`, enqueue to `outbox`.

**Height advance sequence (`try_finalize`, `install_apply_outcome`, `adopt_committed`, `apply_and_advance`, `try_snapshot_sync`):**
- Every height transition advances `SafetyAuthority::advance_height(new_height, finalized_height, finalized_hash)` via `SafetyRecordStore::persist` (`+ db.flush()`) clearing `highest_prevote_round`, `highest_precommit_round`, `last_non_nil_prevote`, `prev_other_non_nil_prevote_round`, `locked`, `highest_proposed`, and setting monotonic `(height = new_height, finalized_height, finalized_hash)`.
- Note for `try_snapshot_sync` (`node/sync.rs:386`) and `adopt_committed`: the block/boundary proof is already verified against `validators` / light-client anchor before calling `advance_height`; if `advance_height` fails on I/O, `SafetyAuthority` quarantines to fail-closed Observer.

### 2.4 Boot reconciliation and legacy quarantine policy

Executed synchronously in `node/bootstrap.rs` / `node/consensus_driver.rs` **before** entering the consensus tick loop:

1. **`SafetyRecordStore::load() == Err(e)`:**
   - Corrupt record, bad BLAKE3 checksum, unsupported outer/inner version, wrong `SafetyRecordIdentity` (`validator`, `chain`, or `shard`), or sled I/O error.
   - Action: **Fail-closed Quarantine** (`AuthorityMode::Quarantined`, `effective_can_vote = false`, loud `eprintln!` + `tracing::error!`). Node may run only as non-signing Observer (or exit non-zero per operator startup policy), never signs.
2. **`SafetyRecordStore::load() == Ok(None)` (absent safety record):**
   - **Exception — Clean Genesis Founding ONLY:** Auto-initialize generation 1 (`height: 1, finalized_height: 0, finalized_hash: [0; 32]`, all floors/locks `None`) via `store.persist(None, ...)` **if and only if ALL** of the following hold:
     1. `is_new_chain_explicit_env()` is `true` (`STELL_NEW_CHAIN=1` or `true`, `stellereum/src/bootstrap.rs:116-127`);
     2. `storage.finalized() == Ok(None)` (zero finalized height);
     3. `storage.latest_state_height() == Ok(None)` or `Ok(Some(0))` (no post-genesis state snapshot);
     4. `storage.vote_watermark() == Ok(None)` and `storage.consensus() == Ok(None)` (zero prior vote/checkpoint records);
     5. `storage.headers` and `storage.by_height` contain no entries at `height > 0`.
   - **Configured Observer (`!is_validator` / `STELL_OBSERVER=1`):** Runs in `AuthorityMode::ObserverOnly` (never signs, may sync/serve RPC). Later promotion to validator still hits the quarantine gate below because `load() == Ok(None)` while `finalized > 0`.
   - **All other cases (`load() == Ok(None)` on an existing store, legacy upgrade, wiped `safety_record_v1`, or validator startup without `STELL_NEW_CHAIN=1` on clean dir):**
     - **FAIL-CLOSED LEGACY QUARANTINE TO OBSERVER** (`AuthorityMode::Quarantined`).
     - Node starts as non-voting **Observer** (syncs blocks, serves RPC, refuses all `propose`/`make_prevote`/`make_precommit` calls) and logs loudly with explicit operator instructions.
     - **Explicit operator-init requirement:** An operator command (e.g. `stelops safety-init` / `stellereum safety-init`) must **only** run after fencing/stopping all legacy processes and remote signers for that validator key, and writes generation 1 via `SafetyRecordStore::persist(None, ...)` with verified `(finalized_height, finalized_hash)` and operator-supplied conservative initial round floors `(highest_prevote_round, highest_precommit_round)` strictly above any round the key could have signed at `finalized_height + 1`. Never manufacture generation 1 automatically from legacy `vote_watermark()` / `ConsensusCheckpoint`.
3. **`SafetyRecordStore::load() == Ok(Some(record))`:**
   - Strictly `decode_canonical(&record.payload)`; any error -> `Quarantined`.
   - Reconcile with `storage` (`finalized()`, `latest_state_height()`, `consensus()`, `vote_watermark()`):
     - If `record.finalized_height > restored_finalized_height`: heal state up to at least `record.finalized_height` before voting (else fail closed).
     - If `restored_finalized_height > record.finalized_height`: advance `SafetyRecordStore` to `(restored_finalized_height + 1, restored_finalized_height, restored_finalized_hash)` **only** after verifying the stored block at `restored_finalized_height` carries a valid `precommit_qc` (else `Quarantined`).
     - At matching height (`record.height == rt.hc.height`):
       - Set `rt.hc.round` at least to `max(highest_prevote_round, highest_precommit_round)` (never rewind below signed round).
       - If `record.locked == Some(l)`:
         - Restore `rt.hc.locked = Some((l.block_hash, l.round))` and `rt.hc.note_value_id(l.block_hash, l.value_id)`.
         - Load `storage.get_block(&l.block_hash)`: verify `blk.compute_hash() == l.block_hash && blk.value_id() == l.value_id`, insert into `rt.blocks`. Because Step A (`put_block + flush`) preceded Step B (`SafetyRecordStore::persist`), absence or mismatch indicates storage corruption/tampering -> stay locked (never drop lock) and quarantine/refuse signing until verified body is restored.
       - Cross-check legacy `vote_watermark()` / `consensus()` if present: conservatively take `max` floor or fail closed on height/finality contradiction.

---

## Resolution 3: File ownership matrix and required test suite

### 3.1 File ownership matrix (for the Rust implementation wave)

| File | Owner / Scope | Exact Responsibility |
|---|---|---|
| `stellereum/src/safety.rs` *(new)* + `stellereum/src/lib.rs` | Heavy Rust Agent (Consensus Safety) | `SafetyAuthority`, `SafetyBackend` (`Durable` / `Ephemeral`), `SafetyRecordPayload` canonical codec, cross-kind `(last_non_nil_prevote, prev_other_non_nil_prevote_round)` state machine, `VoteSigner` trait, legacy quarantine & clean-genesis gate. |
| `stellereum/src/storage.rs` | Heavy Rust Agent (Consensus Safety) | Export any minimal helper needed by `safety.rs` (e.g. `has_non_genesis_blocks_or_headers()` for clean-genesis check, `SafetyRecordStore` integration); preserve existing `SafetyRecordStore` envelope v1 & CAS semantics. |
| `stellereum/src/runtime/mod.rs` | Heavy Rust Agent (Consensus Safety) | Add `safety: SafetyAuthority` field + `with_safety_authority(...)` builder to `ValidatorRuntime`; wire `ValidatorRuntime::new` to `Ephemeral` `SafetyAuthority` for unit/cluster tests while keeping `node/` strictly `Durable`. |
| `stellereum/src/runtime/anchors.rs` | Heavy Rust Agent (Consensus Safety) | Restrict `sign_bytes` (`anchors.rs:3091`) so no runtime path signs votes/proposals outside `SafetyAuthority`; implement `VoteSigner` adapter over `key` / `remote_signer` / `falcon_key`. |
| `stellereum/src/runtime/consensus_step.rs` | Heavy Rust Agent (Consensus Safety) | Seal `make_vote` / `make_vote_at`; wire `make_prevote`, `make_precommit` (require body in `blocks`, Step A `put_block+flush`, Step B `persist`, Step C `sign`, Step D `hc.locked`), `effective_can_vote` (`&& self.safety.can_sign()`), and `adopt_committed` (`advance_height`). |
| `stellereum/src/runtime/mev_sync.rs` | Heavy Rust Agent (Consensus Safety) | Move `propose` signing after `MAX_CONSENSUS_MSG` size check/trim; route `propose` and `restamp_for_round` signatures through `SafetyAuthority::authorize_and_sign_proposal`. |
| `stellereum/src/runtime/apply.rs` | Heavy Rust Agent (Consensus Safety) | Call `self.safety.advance_height(...)` in `try_finalize` (`apply.rs:774`) and `install_apply_outcome` (`apply.rs:541`) and `apply_and_advance`. |
| `stellereum/src/node/consensus_driver.rs`, `stellereum/src/node/policy.rs`, `stellereum/src/node/sync.rs`, `stellereum/src/node/bootstrap.rs` | Heavy Rust Agent (Consensus Safety) | Open `SafetyAuthority::open_from_storage` per shard at boot; enforce legacy quarantine -> Observer; call `safety.advance_height` in `try_snapshot_sync`; fix `flush_outbox` (`policy.rs:1037`) so own valid late-polka `Precommit` is not pruned by `SUPERSEDED_ROUND_LAG`; keep driver floors as non-authoritative liveness dedup only. |
| `stellereum/src/cli/` or `scripts/tools/stelops/src/main.rs` *(if CLI subcommand added in same or follow-up wave)* | Operator CLI Owner (keep disjoint if separate) | Explicit `safety-init` operator recovery command writing generation 1 after fencing legacy signers. |
| `stellereum/tests/safety_authority_integration_tests.rs` *(new)*, `stellereum/tests/masterchain_liveness_tests.rs`, `stellereum/src/node/consensus_driver.rs` (`vote_watermark_tests`) | Heavy Rust Agent (Consensus Safety) | All "failing-before" regressions, crash/fault-injection suite, and updated liveness/cross-kind tests. |

### 3.2 Mandatory test suite (failing-before + crash / fault-injection)

**A. "Failing-before" protocol & safety-boundary regressions (must fail on pre-integration code, pass after):**
1. **`cross_kind_non_nil_prevote_then_late_polka_precommit_refused_prevents_4val_fork`**:
   - Reproduces §1.2 with 4 validators (`[1,1,1,1]` and `[1500,1000,1000,1000]`): $A, B, C$ prevote $(r_0, X)$, $B, C, D$ (or $A, B, D$) prevote $(r_{11}, Y)$ while unlocked, late `r_0` polka arrives at $B, C$.
   - *Fails before:* `make_precommit` signs `precommit(r_0, X)` and $r_{11}$ polka unlocks it -> both $X$ and $Y$ reach valid precommit quorums.
   - *Passes after:* `make_precommit` refuses `precommit(r_0, X)` because a conflicting non-nil prevote $(r_{11}, Y)$ was signed; no second conflicting certificate can form.
2. **`nil_after_conflicting_non_nil_prevote_does_not_bypass_cross_kind_guard`**:
   - Validator prevotes $(r_{10}, Y)$ (non-nil), then prevotes $(r_{11}, \mathrm{nil})$, then receives late polka $(r_0, X)$.
   - *Fails before:* `VoteWatermark` overwrote `(10, Y)` with `(11, nil)`.
   - *Passes after:* `(last_non_nil_prevote, prev_other_non_nil_prevote_round)` retains $r_{10}$ and refuses `precommit(r_0, X)`.
3. **`no_sign_bytes_before_safety_record_persist_in_driver_and_in_process`**:
   - Injects a recording `Signer` + failing `SafetyRecordStore` (or spy checking `SafetyRecordStore` generation inside `Signer::sign`).
   - Exercises **all** signing entry points: catchup nil `make_prevote`, proposal value `make_prevote`, timeout nil `make_prevote`, VEL-2 fast-path `make_prevote`, `make_precommit`, `propose`, `restamp_for_round`, and `Cluster::run_height`.
   - *Fails before:* `sign_bytes` is called before `persist_vote_watermark_before_broadcast`, and failed persist still signs and broadcasts.
   - *Passes after:* `SafetyRecordStore` generation is already incremented on disk **inside** `Signer::sign`, and on persist/flush error `Signer::sign` is called **0 times**.
4. **`late_polka_precommit_after_nil_prevote_still_succeeds_and_not_pruned_by_outbox`**:
   - Preserves `vote_watermark_tests::late_polka_precommit_ignores_the_prevote_floor` (`prevote(r_{11}, nil)` -> `precommit(r_0, X)` allowed) **and** verifies `flush_outbox` at `hc.round = 11` retains `precommit(r_0, X)` instead of dropping it via `SUPERSEDED_ROUND_LAG`.
   - Also verifies `masterchain_liveness_tests::a_late_polka_is_still_precommitted` and `a_late_polka_is_still_precommitted_four_validators` still finalize > 2 heights.
5. **`legacy_absent_safety_record_quarantines_to_observer_except_clean_genesis`**:
   - (i) Store with `finalized > 0` (or `vote_watermark`/`consensus`/`state > 0`, or `STELL_NEW_CHAIN` unset) and `safety_record_v1` empty (`load() == Ok(None)`) -> boots in `Quarantined` Observer (`can_sign() == false`, zero votes/proposals emitted).
   - (ii) Clean dir + `STELL_NEW_CHAIN=1` + height 0 + zero prior votes -> auto-initializes generation 1 (`height = 1, finalized_height = 0`) and enters `Active`.

**B. Crash, durability, and fault-injection tests:**
1. **`crash_after_put_block_flush_before_safety_persist`**:
   - Kill/abort between Step A (`put_block + flush`) and Step B (`SafetyRecordStore::persist`). On reopen: generation unchanged, no precommit signed, node does not claim lock and remains safe.
2. **`crash_after_safety_persist_before_sign_bytes_and_remote_signer_failure`**:
   - Fault-inject `Signer::sign` returning `Err` (or process exit) **after** Step B (`SafetyRecordStore::persist` succeeded). Verify: reservation is **not** rolled back (`generation` stays incremented, `highest_precommit_round` / `highest_prevote_round` and `locked` stay persisted), nothing enters `outbox`, and after restart the node refuses to re-vote at or below that round with any conflicting target.
3. **`injected_put_block_or_flush_or_persist_error_quarantines_and_emits_zero_bytes`**:
   - Fault-inject error in (a) `put_block`, (b) `storage.flush()`, (c) `SafetyRecordStore::persist` / `db.flush()`. Verify `Signer::sign` is never invoked, `hc.locked` is unchanged, `outbox` is empty, and `SafetyAuthority` transitions permanently to `Quarantined` (subsequent votes/proposals refused).
4. **`lock_body_persisted_before_precommit_sign_and_survives_crash_for_restamp`**:
   - Node locks `(target, r_0)` in `make_precommit`, crashes immediately after `sign_bytes` (before `ConsensusCheckpoint` or finality). On reopen: `SafetyRecordPayload.locked` restores `(target, r_0, value_id)`, `storage.get_block(&target)` succeeds with matching `compute_hash` and `value_id`, and a re-stamped proposal of `target` at `r_1 > r_0` is recognized via `same_value` (no `RESTART-SPLIT`).
5. **`missing_or_corrupt_lock_body_on_restart_fails_closed`**:
   - Delete or corrupt `blocks[locked.block_hash]` while `SafetyRecordPayload.locked == Some(...)`. On reopen: lock is **never** dropped, `same_value` stays conservative, and signing is quarantined/refused until verified body is restored.
6. **`make_precommit_without_body_in_blocks_refuses_hash_only_lock`**:
   - Polka arrives without proposal body in `rt.blocks` -> `make_precommit` returns `None`, `SafetyRecordPayload.locked` stays `None`, `sign_bytes` is never called.
7. **`propose_shrink_signs_once_and_prevents_double_propose_across_crash`**:
   - Trigger `propose` pre-gossip trim (`> MAX_CONSENSUS_MSG`) -> `SafetyAuthority` signs **only** the trimmed hash once; after crash/restart at the same `(height, round)`, proposing a different block hash at `(height, round)` is refused.
8. **`height_advance_finalize_adopt_snapshot_sync_persists_new_height_and_clears_old_lock`**:
   - Test `try_finalize`, `install_apply_outcome`, `adopt_committed`, and `try_snapshot_sync` advancing `SafetyRecordStore` generation + `height` + `finalized_height`/`finalized_hash` and clearing prior height's `locked` and floors; verify crash right after advance restarts at `new_height` with clean floors and cannot rewind to `old_height`.
9. **`concurrent_runtime_threads_and_corrupt_record_quarantine`**:
   - Concurrent `make_prevote` / `make_precommit` / `propose` threads on shared `SafetyAuthority` serialize cleanly with monotonic `generation` (zero stale-generation double-signs), and tampered `safety_record_v1` bytes or mismatched `SafetyRecordIdentity` (`validator` / `chain` / `shard`) force fail-closed Observer across all handles.

