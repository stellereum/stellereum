# Cross-cutting LOGIC-BUG sweep (REPORT ONLY)

Date: 2026-11-19 05:58 UTC
Tree: `stellereum-project` @ `24656a6ac` **plus the live working-tree edits**
(the working tree is what the cluster runs; roughly two dozen files were
modified by other agents while this sweep ran — the file changed under the
sweep at least twice, so a hit marked "in-flight" may already be resolved).
Scope: whole repository, with depth on `stellereum/src/{consensus*,
runtime, state_engine, node, sharding, storage, network}` and the infnode
transport helpers they call.
Method: read-only inspection + targeted greps; no source or test edits; no
cargo/test invocation (cargo is serialized and other agents were compiling).
Line numbers are from the working tree at the timestamp above and can shift by
a line or two as the concurrent fixes land.

**Ranking below is by blast radius, not by checklist number.** The checklist
sections follow; every hit is tagged with the checklist item(s) it belongs to.

---

## Top findings (ranked)

| # | Severity | Finding | Primary site |
|---|----------|---------|--------------|
| 1 | **CRITICAL** | 2PC COMMIT obligation is retired after 256 heights (last wire copy at 192 ≈ **46 s** at 240 ms) while the target's PREPARED record never retires. A target that is offline/restarting past that window can never be credited: the source has released the escrow and no one can re-emit COMMIT. | `src/xshard2pc.rs:571-593,653,717` |
| 2 | **CRITICAL** | Mesh "delivered" treats *one* overlay delivery (`n > 0`, an unrelated count) as proof that *every failed direct copy* was delivered, then skips the per-peer broadcast. Empty-target + fallback also returns "delivered" despite the function's own comment. | `src/network.rs:538-547,903-907`, `src/consensus_net.rs:1640` |
| 3 | **HIGH** | Validators do **not** enforce `MAX_BLOCK_PROOF_UNITS` / `MAX_BLOCK_WIRE_BYTES`, and there is **no cap on `block.cross_shard_out.len()`**. A Byzantine proposer can force thousands of Merkle/proof verifications per proposal while staying under the tx-count and gas caps. | `src/runtime/consensus_step.rs:575,595`, `src/mempool.rs:807,816`, `src/runtime/mev_sync.rs:1705-1713` |
| 4 | **HIGH (latent)** | Sealed and plain selections are each capped, but the **union is not**: `sealed_kept ∪ plain_txs` is never passed through `truncate_to_block_caps`, and the sealed loop never accumulates gas. A sealed-heavy pool builds a block its own validators reject (`MAX_BLOCK_TXS`/`MAX_BLOCK_GAS`). | `src/runtime/mev_sync.rs:1153-1275,1365,173` |
| 5 | **HIGH (liveness)** | The full-network-QC split activates at N=192, but at N=191 a 128-seat committee is reachable **only if every single committee member signs** (network 2/3+1 = 128 = whole committee). One offline member, or ordinary stake-weighted sampling variance, stalls every such round. The gate is a **count**, the real predicate is **power**. | `src/consensus/sortition.rs:181-230,306`, `src/consensus/types.rs:2176-2213` |
| 6 | **HIGH** | Height constants still encode 3 s blocks. At ~240 ms: downtime slash after **2.4 s** (`10` heights), jail **4 min** (`1000`), governance timelock / PQ rotation / commission exit window **28.8 min** (`7200`), 2PC terminal retention **61 s**, mailbox quarantine **15 s**. | `src/staking.rs:280,286,333,355`, `src/governance.rs:60`, `src/pq_registry.rs:101`, `src/cn_vrf.rs:65`, `src/xshard2pc.rs:653,684` |
| 7 | **MEDIUM** | 2PC ABORT-ACK is emitted **exactly once** (`decided+1`), even though `source_on_abort_ack` is idempotent and the source re-sends ABORT-REQUEST forever. One lost ACK delays the refund by up to a full terminal-retention window (~61 s; longer if the source's proof anchor has aged out). | `src/xshard2pc.rs:744-757` |
| 8 | **MEDIUM** | Mesh path returns early on payment to the *live* direct targets, so a peer the mesh marked suspected gets **no consensus frames at all** until the 60 s mesh reconnect probe — including `Committed` catch-up frames that the per-peer path deliberately still attempts during failure cooldown. | `src/consensus_net.rs:1640`, `src/network.rs:706-717` |
| 9 | **MEDIUM (transient, now restored)** | During the sweep the working tree briefly had `TEMP-REVERT-FOR-RED-TEST` removing `prepare_cnvrf_v3_epoch_hooks` from the **live sequenced finalize path**. A concurrent agent restored it; it is kept here as a merge gate because the failure (no epoch VDF at activation ⇒ `Beacon(None)` ⇒ no proposer) is silent until activation. | `src/runtime/apply.rs:549-557` |
| 10 | LOW/MED | A record already in the runtime consumed mirror is removed from `xpc_mailbox_seen` but **not from the transport mailbox**, so it is re-fetched and re-tracked every propose (never quarantines). | `src/runtime/mev_sync.rs:1683-1686` |
| 11 | LOW | Receipts are pruned one height *earlier* than bodies (`r.height < keep_from` vs `height + 1 < keep_from`), so the RPC receipt for the oldest retained block is missing while its body is served. | `src/storage.rs:840,888-890` |
| 12 | LOW | `u64::MAX` sentinel semantics are inconsistent: `chain_spec` treats MAX as strictly off, but `is_reshare_active` / `upgrade_exec_active_at` / `cnvrf_v3_is_active_at` return **true** at MAX (raw `>=`). | `src/mev_epoch.rs:1716`, `src/governance.rs:121`, `src/consensus/sortition.rs:672`, `src/chain_spec.rs:53` |
| 13 | LOW | PMM buy failure path refunds burned wUSDT with `let _ = tokens.execute(...)`; if the refund mint fails, the buyer loses the wUSDT while the function only reports the native-mint error. | `src/state_engine/settlement.rs:1314-1325` |
| 14 | LOW | Dead / misleading paths: `call_contract_structured_with_value` has no caller and drops the credit error; `remove_sealed`/`remove_many` have no callers; `apply_and_advance` omits the block-interval metric (`install_apply_outcome` emits it). | `src/state_engine/contracts.rs:377,397`, `src/mempool.rs:1379,2776`, `src/runtime/apply.rs:1134-1180` |

---

## 1. Predicate compared against a different set / count / unit

### 1.1 Mesh "delivered" compares one overlay success with all failed copies — CRITICAL

**Site:** `src/network.rs:538-547` (`MeshDelivery::delivered`),
`src/network.rs:903-907` (`fallback_ok = publish_overlay(...).map(|n| n > 0)`),
`src/network.rs:432-435` (trait contract: "number of local/relayed deliveries"),
`infnode/crates/infnode/src/node.rs:6024-6045` (`publish_overlay` returns `n`
from delivery to *some* subscribers, then fires a best-effort `forward` with
TTL 2), and the consumer at `src/consensus_net.rs:1640`.

**Why it is wrong:** `delivered()` is
`(targets > 0 && direct_failed == 0) || fallback_ok`. `fallback_ok` is a
boolean over "at least one delivery somewhere", not "every failed direct copy
was delivered". It is the same wrong-object comparison as the two bugs that
started this sweep: a filtered success set is compared to the unfiltered
requirement. It is even worse for the empty-target case: the doc comment says
"an EMPTY target set is not a success", but the `|| fallback_ok` disjunct
returns `true` when `targets == 0` and the overlay accepted the publish.
Because the caller now `return`s on `delivered()` (`consensus_net.rs:1640`),
a partial mesh failure — or a fully suspected mesh — **skips the per-peer
broadcast** that is the only route with per-peer acknowledgement. The failed
copy's only remaining chance is the overlay's best-effort forward. The
caller's log still says the delivery was complete.

**Impact:** loss of consensus frames (votes/proposals/Committed catch-up) to
exactly the peers whose direct link is unhealthy. This is a liveness bug that
looks green in the metrics. It also re-introduces the double-send's inverse:
the peer that needs the frame most is the one whose fallback was "assumed".

**Fix (minimal):** do not let a best-effort overlay publish stand in for
per-target delivery. Either (a) only `return` when `targets > 0 &&
direct_failed == 0`, and always run the per-peer broadcast when
`direct_failed > 0` (accept the documented duplicate), or (b) make
`publish_overlay` report the *set* of peers acknowledged and require it to
cover the failed target set. In both cases the empty-target case must remain
false unless every mesh member is proven covered.

### 1.2 QC-split gate compares a head count against a power predicate — HIGH

**Site:** `src/consensus/sortition.rs:181-230` and `:306`
(`qc_split_required(height, validator_count)`), consumed at
`src/consensus/types.rs:2018,2155`; the actual acceptance rule at
`src/consensus/types.rs:2176-2213` (`micro_cert_meets_quorum` →
`pq_micro_required_power` at `src/consensus/sortition.rs:155-165`).

**Why it is wrong:** the gate fires on `validators.len() >= 192`. But the
condition it is trying to proxy is `W_committee >= floor(2*W_network/3) + 1`.
At N=191 the doc itself says the µQC is reachable "only with a UNANIMOUS
committee": 128 committee seats and a network requirement of
`floor(2*191/3)+1 = 128`. Any one committee member offline, or any ordinary
stake-weighted sampling variance in the 128-seat draw (expected share is
128/191 = 67.02 %, barely above 2/3), makes the round's µQC impossible. The
code then has no full-network CEC fallback because the count gate is still
closed. The same applies for every N in roughly 170..191 with increasing
probability. A number-of-names threshold is not the same unit as a stake-power
threshold.

**Impact:** liveness cliff just below the documented "first impossible size";
wasted rounds and, on a weak validator set, an apparent halt at N=191. A
restake that changes stake distribution changes the effective threshold,
which is exactly what the comment claims the count rule prevents.

**Fix (minimal):** compute the predicate from the drawn committee's power on
the producer and verifier path: require the full-network CEC whenever
`committee_power < pq_full_required_power(network_power) + safety_margin`
(or simply whenever the committee would need unanimity:
`committee_power <= network_required`). If a constant gate is preferred for
rollout reasons, move it to 191 and document that the µQC is only advisory at
and above that size; the current 192 leaves a one-seat liveness trap.

### 1.3 `u64::MAX` sentinel used with opposite meanings — LOW

**Site:** `src/chain_spec.rs:53` and its test at `:203-217` define MAX as
strictly `GatedOff`; `src/mev_epoch.rs:1716` (`>=`), `src/governance.rs:121`
(`>=`), `src/consensus/sortition.rs:672` (`>=`) return **active** at MAX.

**Why it is wrong:** the project has a documented one-way convention
(`u64::MAX ⇔ GatedOff`, and `is_active(..., u64::MAX) == false`). Four
live predicates use the opposite convention. Today no live height reaches
MAX, so the practical impact is a latent inversion: any future code path that
passes an uninitialized/sentinel height (a default `u64::MAX`) turns a
"disabled" feature ON instead of leaving it off, and the two answers for the
same `(gate, height)` disagree.

**Fix (minimal):** use `height != u64::MAX && height >= threshold` in every
activation predicate (or route all of them through `chain_spec::is_active`),
and add one cross-module pin test that asserts the convention for every
`*_ACTIVATION_HEIGHT` constant.

---

## 2. Retry / fallback that duplicates work or sends twice

### 2.1 2PC COMMIT re-emission stops long before recovery is possible — CRITICAL

**Site:** `src/xshard2pc.rs:571-593` (`source_action`),
`:653` (`XPC_TERMINAL_RETENTION_HEIGHTS = 256`), `:717-724`
(`is_retired`), `src/state_engine/xshard.rs:318-352`
(`prune_terminal_xpc_records`, runs on every applied block), and
`src/runtime/mev_sync.rs:1810-1857` (the only producer of COMMITs).

**Why it is wrong:** after the target's PREPARE-ACK, the source commits and
re-emits COMMIT at `elapsed == 1` and every `XPC_COMMIT_REEMIT_INTERVAL` (64)
while `elapsed < 256`; at `elapsed == 256` `source_action` returns `Idle`.
`is_retired` then deletes the source record at `decided_height + 256`. The
last COMMIT can therefore be produced at **elapsed 192**, i.e. ~46 s at
240 ms. The target's side keeps a PREPARED record (it never retires: `:719`)
and has no way to obtain the decision if it misses that window:
`target_on_commit` needs the source's COMMIT, and a re-sent PREPARE-ACK from
the target reaches `source_on_prepare_ack` which is `Noop` for an
already-COMMITTED record (and `Refused` once the source record is gone).
The target's inbound mailbox also quarantines unadmittable records after 64
local heights (`:684`), and a header older than the 512-height registry
window can no longer be anchored. There is no pull-from-source-block or
resume-by-ack path.

**Impact:** permanent value loss / permanently uncredited recipient. A target
validator that is down for ~1 minute at the new block rate (or a node
restoring from a snapshot older than the decision, or a target whose mailbox
copy aged out while it was syncing) never credits a transfer the source
already committed and whose escrow was released. This is exactly the
"retention vs re-emit window" shape and it is much more likely at 240 ms
than at 3 s.

**Fix (minimal):** the source must keep the decision until it has positive
evidence the target applied it (there is currently no COMMIT-ACK), or the
retention must be sized to the sync/repair window rather than 256 heights.
Concretely: raise `XPC_TERMINAL_RETENTION_HEIGHTS` to a value expressed as a
target wall-clock duration at the minimum block interval (e.g. ≥ 1 day of
heights), keep emitting at the low cadence for that whole window, and only
then retire. A stronger fix is to add a COMMIT-ACK (or treat the target's
periodic PREPARE-ACK for a COMMITTED source record as a pull hint and re-emit
COMMIT), so retirement is driven by completion rather than by a constant.
At minimum, do not let `source_action` go Idle before `is_retired`.

### 2.2 ABORT-ACK is one-shot although its consumer is idempotent — MEDIUM

**Site:** `src/xshard2pc.rs:744-757` (`should_reemit_ack`, `Aborted` arm is
`height == decided+1`), `:766-774` (`target_action_at`), and the source's
forever-running abort request at `:571-577`.

**Why it is wrong:** the doc justifies the single emission with "a copy is a
duplicate that the source's idempotent `source_on_abort_ack` refuses". That is
precisely backwards for loss recovery: because the consumer is idempotent, a
re-sent ABORT-ACK is harmless and is the only way to recover a lost one. The
source re-emits ABORT-REQUEST every block until it is refunded; the target
sits on an `Aborted` record and returns `Noop` for every request, so it emits
nothing more. The refund is delayed until the target's Aborted record retires
(decided+256) and a later request recreates it — and that recreation can fail
if the source's proof anchor has fallen out of the 512-height registry
window.

**Impact:** refund/escrow stuck for at least a terminal-retention window
(~61 s at 240 ms), potentially much longer when the anchor window is also
involved. No double-refund is possible, so the safe fix is simply to resend.

**Fix (minimal):** re-emit ABORT-ACK once per `XPC_ACK_REEMIT_INTERVAL` while
the record is `Aborted` (same cadence as PREPARED acks), and keep it bounded
by record retirement. Update the test that currently pins "exactly one
authorisation" (`src/xshard2pc.rs:939,960`) to pin "at most one per window,
idempotent at the source".

### 2.3 Mesh duplicate-suppression now suppresses the *only* remaining route — CRITICAL

See §1.1. Note the shape: the previous fix (correctly) stopped comparing
`direct_ok` to the raw configured peer count, but the new `delivered()`
predicate substitutes a *different* wrong count (overlay deliveries > 0). It
is the same bug one level up.

---

## 3. Counter / metric / log reports a different thing than its name

### 3.1 "mesh direct delivery complete" can be logged/proven by a local/partial overlay count — CRITICAL

**Site:** same as §1.1 (`MeshDelivery::direct_ok/direct_failed/targets/
fallback_ok`, `src/network.rs:525-547`; log at `src/consensus_net.rs:1653-
1663`).

**Why:** the warning line and the `delivered()` decision both use `targets`
(which excludes suspected peers) and `fallback_ok` (at least one overlay
delivery). Neither reports "every intended validator has a delivery proof".
The operator-visible "complete" therefore says nothing about the peer that
was actually skipped.

**Impact:** the failure is invisible exactly when the mesh is degraded — the
same class as "delivered complete" vs the filtered target list.

**Fix:** report the intended set (mesh members) and per-target outcome, and
make "complete" mean `direct_ok + overlay_acked == intended` for the actual
peer set, not `targets`.

### 3.2 Block-interval metric is missing on the adopt/walk path — LOW

**Site:** `src/runtime/apply.rs:528` and `:760` emit
`observe_block_interval`; `apply_and_advance` (`:1134-1180`) sets
`last_progress_at` without emitting.

**Why:** a node that primarily adopts/walks finalized blocks (a lagging
observer or a validator catching up) reports a cadence only for locally
decided blocks, so the "block interval" gauge is biased high (or silent) on
exactly the nodes operators use to measure catch-up. It does not affect
consensus.

**Fix:** call the same emission in `apply_and_advance` before resetting
`last_progress_at`, or move the emission into a single helper used by all
three finalize paths.

### 3.3 Dead counter-adjacent path: `call_contract_structured_with_value` — LOW

**Site:** `src/state_engine/contracts.rs:377-399` (no callers; grep across the
tree finds only the definition).

**Why:** it debits the caller, then `let _ = self.credit_native(address,
value).await;` and proceeds to a successful call outcome. If the credit fails
(overflow), the value is silently destroyed and the method reports the call,
not the transfer. The method name promises a value transfer the body does not
guarantee.

**Fix:** treat it as dead code and delete it, or make the credit failure
return a failed outcome and refund the debit. Either way, no `let _ =` on a
value path.

---

## 4. A bound checked in one path and bypassed in another

### 4.1 Validators do not enforce the wire / proof-unit caps, and cross-shard output has no count cap — HIGH

**Site:** proposer-side caps: `src/mempool.rs:807` (`MAX_BLOCK_WIRE_BYTES =
24 MiB`), `:816` (`MAX_BLOCK_PROOF_UNITS = 2048`), enforced only in
`select_multi` (`:2911,2915`) and `truncate_to_block_caps`
(`src/runtime/mev_sync.rs:173-195`). Validator/side checks at
`src/runtime/consensus_step.rs:575` (tx count), `:595` (gas) and the adopt
twin at `:2250,2257` — no wire/proof check. Cross-shard: the proposer's
`is_control` budget (`src/runtime/mev_sync.rs:1705-1713`) excludes legacy
`Transfer` records and there is no total `cross_shard_out` bound anywhere
(grep for `cross_shard_out.len()` finds only hashing in
`src/sharding/block.rs:858,877`).

**Why it is wrong:** the comments at `mempool.rs:803-816` say these caps exist
because "gas-valid does not mean gossipable or verifiable-in-time". The
mempool/proposer honors them; the consensus validator does not. A Byzantine
proposer can therefore include up to `MAX_BLOCK_TXS` transactions whose total
wire bytes exceed 24 MiB (bounded only by the 32 MiB frame cap) and whose
proof units far exceed 2048, forcing every validator to verify more
attestations than the protocol's own time budget. The same proposer can stuff
`cross_shard_out` with thousands of legacy transfer records (each requiring a
Merkle/anchor check at `consensus_step.rs:436`) because only 2PC control
records are budgeted.

**Impact:** per-proposal validation CPU/bandwidth blow-up, missed round
timeouts, and a cheap way to stall a sharded height. It also breaks the
"proposer can never build a block its own validators reject" invariant in the
opposite direction: the validator accepts what the proposer-side policy says
is unverifiable.

**Fix (minimal):** in `validate_proposal_unaligned` and `adopt_committed`,
recompute the same `sum estimate_tx_wire_bytes` and
`sum count_tx_proof_units` and refuse over-cap blocks (both helpers are
already `pub`). Add a total cross-shard record cap (e.g.
`MAX_CROSS_SHARD_RECORDS_PER_BLOCK`, applied to `cross_shard_out.len()` in
both propose and validate), and count *every* record kind, not just control
ones.

### 4.2 Sealed + plain union bypasses `MAX_BLOCK_TXS` / `MAX_BLOCK_GAS` — HIGH (latent)

**Site:** `src/runtime/mev_sync.rs:1153-1275` (sealed loop: caps count at
`:1156`, never accumulates gas/wire/proofs), `:1338-1352` (plain selection
uses the **full** `MAX_BLOCK_TXS`/`MAX_BLOCK_GAS` budgets), `:1365`
(`sealed_kept.chain(plain_txs)` with **no** `truncate_to_block_caps`), and
`src/runtime/consensus_step.rs:575,595` (validators reject over-cap blocks).

**Why it is wrong:** each selector is bounded independently; the concatenation
is not. With a sealed pool of up to `max_size / 4` envelopes and a plain pool,
the block can exceed 10 000 txs and 500 M gas by up to the sealed share, and
the sealed loop does not accumulate gas at all, so sealed-only blocks can
already exceed the gas cap. The validator's `MAX_BLOCK_TXS`/`MAX_BLOCK_GAS`
check then rejects the proposer's own block. The prebuild branch calls
`truncate_to_block_caps` (`:1330`); the sealed path returns directly, which is
the asymmetry.

**Impact:** a missed height whenever the sealed path is active and the pools
are full enough; the proposer builds a block no honest node will vote for. It
is latent while the MEV epoch seal has no material, but the DKG pathway is
live code.

**Fix (minimal):** after the union at `:1365`, call
`Self::truncate_to_block_caps(&mut txs)` (it preserves the sealed-first
order), and accumulate gas/wire/proofs in the sealed loop so the sealed set
alone can never cross the caps.

### 4.3 Round-retention cap bypassed when the polka round is the oldest — MEDIUM

**Site:** `src/consensus/engine.rs:2059-2084` (`prune_old_rounds`):
`while retained > MAX_RETAINED_VOTE_ROUNDS { ... if oldest == observed_polka
{ break; } ... }`.

**Why it is wrong:** the `break` exits the loop instead of skipping the polka
round, so once the polka is the oldest retained round the cap is never
enforced again for that height; every later round stays. A long-wedged height
can grow one vote bucket per round (`MAX_RETAINED_VOTE_ROUNDS` is 4096 and
`REPHASE_SCAN_WINDOW` is also 4096; at ~800 ms rounds that is ~55 min, which
the live history shows is reachable). The new test
`retained_round_cap_holds_when_the_polka_round_is_the_oldest` in
`src/consensus/tests/core.rs:1534` currently demonstrates the failure.

**Impact:** unbounded memory/scan growth inside one stuck height, and the
promised DoS bound is not delivered.

**Fix (minimal):** instead of `break`, select the oldest round that is **not**
the polka and evict that; only break when the polka is the only round left.
(Another agent already added the failing test in the working tree; the code
has not switched to the skip-the-polka loop yet.)

### 4.4 Actor-mailbox cap is absent from `replay_historical_block` — LOW

**Site:** `src/runtime/apply.rs:946-1110` (no `check_actor_cap`), while the
propose/proposal/adopt/finalize/walk paths all call it
(`consensus_step.rs:1137,2379`, `apply.rs:664`, `node/sync.rs:1000`).

**Why:** replay is QC-bound history, so a *new* over-cap block cannot be
injected through it; but a block produced before the cap existed replays with
the engine's defensive clamp and the root-invisible leftover that the cap
comments explicitly forbid. The next post-state check will catch a divergence,
so this is fail-loud rather than a fork, but it is the one decision boundary
that does not use the shared predicate.

**Fix:** call `self.check_actor_cap(block).await?` in `replay_historical_block`
(or document in one place why replay is the sole exception and assert the
clamp is deterministic).

---

## 5. Silent drop where surrounding code assumes delivery

### 5.1 Mailbox entry removed from the tracker but not pruned from the transport — LOW/MEDIUM

**Site:** `src/runtime/mev_sync.rs:1683-1686`:

```rust
if self.consumed_cross_shard.contains(&key) {
    self.xpc_mailbox_seen.remove(&msg.msg_id);
    continue;                    // no prune_ids.push(...)
}
```

Compare the next branch (`:1687-1710`), which removes the tracker entry **and**
pushes to `prune_ids`, and the later completion branch (`:1735-1745`), which
also pushes.

**Why it is wrong:** removing the local first-seen entry makes the record look
brand new next proposal, so it is re-inserted at the current height and can
never age out to quarantine. On the non-draining node-local KV transport
(`P2pNetworkAdapter::fetch_cross_shard_inbound` reads the KV index, it does not
remove entries), the record stays in the mailbox forever and is re-fetched,
re-decoded and re-checked on every propose that node builds (up to ~4/s on a
solo node at 240 ms). The P2P gossip
transport happens to drain the inbox on fetch, so it escapes the repeat-work
half, but the node-local KV index is still never cleaned. The surrounding code
assumes every consumed record is pruned (`prune_ids` is the only transport
cleanup).

**Impact:** mailbox growth and repeated work proportional to the number of
consumed cross-shard messages, not to the live backlog; the quarantine bound
never applies to these entries on the KV transport.

**Fix (minimal):** `prune_ids.push(msg.msg_id)` in that branch (and in the
later `completed_cross_shard` branch) before `continue`.

### 5.2 PMM refund mint error ignored — LOW

**Site:** `src/state_engine/settlement.rs:1314-1325`.

**Why:** the native mint failure is reported, but the compensating wUSDT
mint that refunds the already-burned buyer funds is `let _ =`. If that token
mint also fails (token cap/feature gate), the buyer loses the wUSDT while the
caller only sees the native error. A value path must not have a silent
compensating failure.

**Fix:** propagate/log the refund failure distinctly and fail the whole buy
with an explicit "refund failed" error; never return with a value still
burned.

### 5.3 Dead no-caller helpers — LOW

`Mempool::remove_sealed` (`src/mempool.rs:1379`) and `Mempool::remove_many`
(`:2776`) have no callers. `remove_sealed` is reachable in spirit via
`prune_confirmed` (`:3153-3168`), so this is not a live leak, but a future
caller that assumes `remove` handles sealed entries would leak them; the
method body promises a behaviour nothing invokes. Delete them or wire
`remove`/`remove_many` to cover sealed entries as well.

---

## 6. Stale copy read instead of applied state

No new high-confidence hit found beyond the already-fixed snapshot-replay
capture. Verified specifically:

* `install_apply_outcome` / `apply_and_advance` read `self.validators` before
  `refresh_validator_set_from_staking` (so the light anchor is checked under
  the height's set) and install the staged set only after the height advance.
* `validator_set_for_height` answers a staged set only at/above its
  activation and otherwise walks the bounded history; the `h >= hc.height`
  branch is correct for future queries.
* The snapshot bytes are captured at submit quiescence and bound to the
  submitted height (`pending_snapshot_xshard`), and the worker re-checks the
  certified post-height root before cloning.
* `apply_cross_shard_consumptions` snapshots `xpc_in_block` before the loop
  and uses the engine's committed sets after each atomic claim.

One residual **observation** (not a new bug): `apply_and_advance` does not
emit the block-interval metric (§3.2), and the `record_apply_outcome` mempool
feedback uses the block's outcome, not a per-tick copy, so the stale-mirror
class is clean on the paths inspected.

---

## 7. Unit / scale mismatch and window-boundary bugs

### 7.1 Height windows still assume 3 s blocks — HIGH

**Sites and the arithmetic at ~240 ms** (the prompt's live rate; the code
itself runs `STELL_MIN_BLOCK_MS` as low as 50 ms):

| Constant | Heights | At 240 ms | Doc claim |
|---|---|---|---|
| `DOWNTIME_MISS_THRESHOLD` (`staking.rs:280`) | 10 | **2.4 s** | none (but 10 consecutive missed certificates is the *whole* slash trigger) |
| `DOWNTIME_PENALTY_COOLDOWN` (`:286`) | 100 | 24 s | "minimum between slashes" |
| `JAIL_RELEASE_DELAY_HEIGHTS` (`:333`) | 1000 | **4 min** | "≈50 min at 3 s" |
| `COMMISSION_EFFECT_DELAY_HEIGHTS` (`:355`) | 7200 | **28.8 min** | "≈6 h at 3 s" |
| `GOV_TIMELOCK_HEIGHTS` (`governance.rs:60`) | 7200 | **28.8 min** | "≈6 h at 3 s" |
| `PQ_ROTATION_DELAY_HEIGHTS` (`pq_registry.rs:101`) | 7200 | **28.8 min** | "≈6 h at 3 s" |
| `EPOCH_LEN` (`cn_vrf.rs:65`) | 7200 | **28.8 min** | "≈6 h at 3 s" |
| `MEV_KEM_ROTATION_DELAY_HEIGHTS` (`mev_kem_registry.rs:90`) | 7200 | **28.8 min** | "≈6 h at 3 s" |
| `XPC_TERMINAL_RETENTION_HEIGHTS` (`xshard2pc.rs:653`) | 256 | **61 s** | "recoverable" |
| `XPC_MAILBOX_QUARANTINE_HEIGHTS` (`:684`) | 64 | **15 s** | "bounded mailbox" |
| `REGISTRY_ANCHOR_WINDOW` (`sharding/xshard.rs:485`) | 512 | 2 min | header anchor window |

**Why it is wrong:** these constants are calibrated and documented in wall
time at 3 s/block, but the live chain now produces blocks roughly 12.5× faster.
The safety semantics are not preserved: a validator that misses 10
certificates in a row is slashed and jailed after a **2.4-second** hiccup, and
the governance timelock / PQ rotation / commission exit window shrink from
6 hours to under 30 minutes. The 2PC constants (61 s retention, 15 s
quarantine) are too short to ride out a normal restart or catch-up, which is
what turns finding 1 from a theoretical edge into a likely one.

**Impact:** economic slashing of honest validators on ordinary network
jitter; governance/commission/key-rotation safety windows no longer provide
the reaction time their rationale promises; 2PC retry windows too short for
sync. This is the highest-leverage operational item in the report after the
2PC retention bug.

**Fix (minimal):** introduce a single `BLOCKS_PER_MINUTE`/`BLOCK_INTERVAL_MS`
protocol constant (frozen with the activation) and derive the height constants
from the intended wall-clock durations, or at minimum retune every constant
above with a spec update + audit note and update the "≈ … at 3 s" comments so
operators do not rely on stale numbers. For downtime, 10 consecutive heights
at a sub-second tempo is almost certainly not the intended outage detector;
express it as "missed >= N seconds of heights" via the protocol constant.

### 7.2 Receipts pruned before the retained body set — LOW

**Site:** `src/storage.rs:840` (`r.height < keep_from`) vs `:888-890`
(`height + 1 < keep_from` for bodies); the prune job runs them in one
`PersistJob::Prune` (`:3409-3411`).

**Why it is wrong:** the body retention rule keeps the boundary height
`keep_from - 1` so the retained suffix links to genesis; the receipt rule
deletes that same height's receipts. A caller asking for the receipt of the
oldest block the node still serves as a body gets "not found" even though the
block is retained and its receipt is notionally in the same retention class.

**Impact:** one-height hole at the retention boundary for receipt RPC /
explorer backfill. No consensus impact.

**Fix:** share the boundary predicate with `body_is_removable` (i.e. prune
receipts only when `r.height + 1 < keep_from`), or document that receipts are
intentionally retained one height shorter.

### 7.3 191/192 committee boundary — HIGH

See §1.2. It is both a boundary bug (`191` is the last count that can carry a
128-seat committee only with unanimity) and a unit bug (count vs power).

---

## 8. Ordering assumptions broken by the ~240 ms block rate

Covered by §7.1. The specific "fixed window" offenders are:
`DOWNTIME_*`/`JAIL_RELEASE_*` (economic), `GOV_TIMELOCK_HEIGHTS`,
`COMMISSION_EFFECT_DELAY_HEIGHTS`, `PQ_ROTATION_DELAY_HEIGHTS`,
`EPOCH_LEN`/`V3_COMMIT_LOOKAHEAD_BLOCKS`, `XPC_*` retention/quarantine, and
`REGISTRY_ANCHOR_WINDOW`. Also note `MAX_RETAINED_VOTE_ROUNDS` /
`REPHASE_SCAN_WINDOW` (rounds, not milliseconds) are unaffected by the block
rate themselves, but the time to reach 4096 rounds shrinks in wall time.

No **new** "once per tick" budget bug was found: `TICK_MS` stays 50 ms and the
compact-gossip budgets are per tick and bounded. During the sweep another
agent replaced the flat catch-up budget with the gap-aware
`catchup_pass_budget_ms` (`src/node/policy.rs`), which addresses the one
operational concern (a 250 ms budget equal to one block interval); it is
best-effort and does not affect correctness either way.

---

## 9. Configuration defaults that silently disable a feature

### 9.1 `u64::MAX` sentinel inversion — LOW

See §1.3. `is_reshare_active(u64::MAX)` and `upgrade_exec_active_at(u64::MAX)`
are true; `chain_spec::is_active(..., u64::MAX)` is false. The environment
knobs themselves are read per call in most places, which is intentional for
node-local policy; the consensus-affecting gates are compile-time constants
(correct). No env-read-once-at-startup bug was found on a consensus path.

### 9.2 Feature flags parsed as exact `"1"` — LOW

`INFNODE_MIGRATION_PUSH` (`infnode/.../migration.rs:277`) and
`INFNODE_REWARDS` (`infnode/.../main.rs:646`) enable only when the value is
exactly `"1"`; `true`/`yes`/`on` silently disable. The docs use `=1`, so this
is a footgun rather than a logic error, but it is the checklist's "flag parsed
as `1` only" shape. Fix: accept a shared truthy parser (or fail loudly on an
unrecognized non-empty value instead of silently disabling).

### 9.3 Deliberate dormant gates (verified, not bugs)

`DANDELION_ENABLED = false` (const, test/sim only), `QC_SPLIT_ACTIVATION_HEIGHT
= u64::MAX`, `CHAIN_BINDING_ACTIVATION_HEIGHT = u64::MAX` (release ignores
env, debug honors it), `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX` and
`CNVRF_V3_ACTIVATION_HEIGHT = u64::MAX` are all documented freezes. They are
listed here so a future reviewer does not mistake them for silent failures;
the only defect is the inconsistent MAX-at-maximum behaviour in §9.1.

---

## 10. Dead code paths that still look active

### 10.1 `call_contract_structured_with_value` — LOW

`src/state_engine/contracts.rs:377` has no caller and drops the credit error
(§3.3). Delete or repair.

### 10.2 `Mempool::remove_sealed` / `remove_many` — LOW

`src/mempool.rs:1379` and `:2776` have no callers. `prune_confirmed`
(`:3132-3169`) is the real sealed-removal path and does handle included
sealed envelopes, so this is dead code, not a live leak. The risk is a future
caller assuming `remove` covers sealed entries; wire them together or remove
the unused methods.

### 10.3 `MeshDelivery::delivered` doc vs body — CRITICAL in effect

The method is used (good), but its body contradicts its own "empty target is
not a success" comment because of `|| self.fallback_ok` (§1.1). This is the
"method name promises behaviour the body does not implement" shape.

### 10.4 Dead comments that describe the old design — verified

The large comments in `network.rs:1385-1392` ("a body is only ever written by
`broadcast_block`") are stale: `broadcast_block` is only used for genesis; the
live path uses `retro_publish_blocks` + `persist_block_header`. This did not
produce a logic bug in the paths inspected, but it misdirects future audits.

---

## Verified clean (specifically checked, no defect found)

* **2PC COMMIT credit counter (today's fix):**
  `state_engine/xshard.rs:606-632,790-792` increments `credited` only when
  the COMMIT transition actually advanced, and a replay is a `Noop`; the test
  at `:1623-1741` pins 1 credit / balance + amount / replay 0. Correct.
* **Mesh "attempted vs configured" predicate (today's fix):**
  `targets` now comes from `direct_targets()`, not the config peer count
  (`network.rs:710-717`). Correct apart from the new `delivered()` problem.
* **Bridge confirmation depth & future-head refusal:**
  `bridge.rs:1851-1881` (TON) and `:2113-2146` (EVM) both refuse a source
  height ahead of the finalized head before the depth comparison.
* **Distinct bridge signer counting:** `bridge.rs:604-634` dedups before
  counting, refuses unknown/non-Falcon signers, and fails closed on an empty
  set.
* **Mempool per-sender quota:** shared between sealed and plain admission
  (`mempool.rs:1309-1318` and `:2321-2323`); sealed quota is separately
  bounded (`:1323,858`).
* **Mempool eviction / reservation rollback:** `prune_confirmed` removes
  plain, activation-buffered and sealed entries and releases the sender slots
  (`:3132-3169`).
* **Snapshot cadence:** `snapshot_cadence.rs` is pure, its floor is
  `height - last > interval`, and the submit site asserts on two certified
  roots (`consensus_driver.rs:3710-3720`); no stale/empty idle skip found.
* **Governance tally:** frozen electorate + per-voter weights at propose
  (`governance.rs:1157-1205`), idempotent same-choice votes, different-choice
  refused, and the lock amount equals the counted weight. Finalize and
  execute-time recheck use the same `turnout >= electorate*quorum_bps/10000`
  formula (`:1685,1987`).
* **PQ rotation boundary:** pending key is authoritative at exactly
  `effective_height` on both `get_active_key` and `apply_rotation`, and the
  superseded interval is half-open (`[activated_at, superseded_at)`), so no
  height resolves two keys.
* **Snapshot anchor arithmetic:** `boundary_hash` is the QC-verified hash at
  `next_height-1`, and `state_root` is the header at `next_height`; under the
  chain's "header commits to the state BEFORE its own block" convention these
  are the same state. Tail window clamps at height 1 and at genesis.
* **Consensus block checks:** height/prev-hash/proposer/timestamp/order
  root/QC/fee floor/actor cap are all present on proposal, adopt and finalize;
  the only missing caps are wire/proof-unit (finding 4.1).
* **2PC control-record budget:** proposer (`plan + openings + inbound <= 16`)
  and validator (`count(control) > 16` refuses) agree; the opening budget
  reserves four slots for inbound control records.
* **Actor-mailbox cap:** static half in the sync validator, backlog half on
  propose/proposal/adopt/finalize/walk (`apply.rs:137-162`, callers at
  `consensus_step.rs:1137,2379`, `apply.rs:664`, `node/sync.rs:1000`);
  `replay_historical_block` is the one exception (4.4).
* **Block timestamp:** monotone vs the resolved parent and bounded by
  `MAX_TIMESTAMP_JUMP_SECS`; the height-1/genesis exception is explicit and
  deterministic (`consensus_step.rs:39-85`).
* **Fee floor:** validator and proposer share
  `Mempool::required_fee_for_tx` plus the consensus penalty, and a contended
  mempool read fails closed (`consensus_step.rs:655-716`).
* **Round-cap failure (already under concurrent fix):** the bug is real
  (§4.3) and another agent has already added the red test
  (`consensus/tests/core.rs:1534`); the code has not yet been switched to
  skip-the-polka eviction.

---

## In-flight working-tree hazards (do not merge as-is)

1. **`src/runtime/apply.rs:549-557`** — **Observed, then restored during this
   sweep.** At 05:58 UTC the file carried
   `// TEMP-REVERT-FOR-RED-TEST: self.prepare_cnvrf_v3_epoch_hooks(...)` in
   `install_apply_outcome`, the path used by the live node loop
   (`consensus_driver.rs:3277-3300`). By 06:05 UTC a concurrent agent had
   restored the call. Keep this as a merge gate: if the temporary revert is
   reintroduced, the live path never dispatches the epoch VDF once
   `CNVRF_V3_ACTIVATION_HEIGHT` flips, so the boundary block has no beacon
   and the fail-closed schedule carries no proposer. Add a regression test
   that asserts the sequenced path calls the hook, not just the inline one.
   (Impact is latent while the activation gate is `u64::MAX`.)
2. **`src/consensus_net.rs:1640` + `src/network.rs:538-547`** — the new
   `delivered()` early return is the mesh regression described in §1.1. The
   adjacent commit fixed the raw-peer-count comparison but replaced it with
   an overlay-count proxy.
3. **`src/consensus/engine.rs:2059-2084`** — the round-cap test is red; the
   code still has the `break` (§4.3). Do not merge the test alone.

---

## Suggested order of repair

1. §1.1 mesh completion proof and §2.1 2PC COMMIT retention (value/liveness,
   both are "wrong set/count" bugs).
2. §4.1 validator-side wire/proof/cross-shard caps (Byzantine DoS).
3. §4.2 sealed+plain union caps and §5.1 stale mesh targets (cheap, direct).
4. §7.1 retune/derive the height constants at the new tempo; this also makes
   §2.1/§2.2 windows meaningful.
5. §1.2 QC-split power gate and §4.3 round retention.
6. The LOW cleanups (§5.2, §7.2, §9/§10).
