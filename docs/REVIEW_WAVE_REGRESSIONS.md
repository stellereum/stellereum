# REVIEW_WAVE_REGRESSIONS — independent regression review of `3f4b80e16..24e2a1dca`

**Scope.** `git diff 3f4b80e16..24e2a1dca` (HEAD `24e2a1dca`: mega wave `8668d9d1c`,
compact-gossip wiring `9f7173b68`, 2PC credit count `2f5ed83d2`, test pinning
`24e2a1dca`, plus `1251fb4ea`). All `file:line` references below are lines of
**`24e2a1dca`** (the reviewed commit), not of the dirty working tree.

**Stance.** Read-only. No `src/**` edit, no node touched, no restart. Only
targeted tests were run (`CARGO_BUILD_JOBS=2`); full suite was **not** run.
The review was written with no access to the authors' intent beyond code,
comments and the in-tree docs.

> **Working tree note.** The checkout is dirty *while this review was being
> written*: other sessions are updating `docs/UPGRADE_AND_RECOVERY.md`,
> `docs/COMPLETENESS_GAP_ANALYSIS.md`, `docs/REVIEW_STATE_ECONOMICS.md`,
> `docs/PENTEST2_*.md`, etc. Those edits are **not** part of the reviewed
> range. Where a stale pin has already been fixed in the dirty tree, that is
> stated in §2.3 so nobody mistakes the WIP for the committed state.

---

## 0. Verdict at a glance

| # | Item | Verdict |
|---|------|---------|
| 1 | Changed defaults / gates consistent with every gate, doc and test pin | **FAIL** — 5 gates are internally consistent, but multiple committed docs still assert the old lists; `GOV_OPS` is not in `chain_spec`; the XPC env is described as live in `PROTOCOL.md` / `scripts/local-cluster.*` after being retired |
| 2 | `apply.rs` step 5e ordering and `has_due_governance` fast path | **PASS** for ordering and for the skip check; **FAIL** as a *system* because activating 5e at genesis makes the pre-existing DET-01 reward-resolution hazard reachable (R1) |
| 3 | `mempool.rs` carrier branch vs PQ1/SF1 and fee arithmetic | **PASS** for shadowing/PQ1/SF1 and for overflow/underflow; **FAIL** for fee semantics (carrier surcharge is never charged at execution) and for the nonce/value invariant not being re-checked on the block path (R6, R7) |
| 4 | `network.rs` mesh fallback / double-send | **PASS for production** — the direct mesh is *not wired* to any consensus send, so it cannot double-send today. If wired as-is, the fallback broadcast would duplicate to already-reached peers; receiver de-duplication is idempotent (votes, proposals, commits), so vote counts would not change (R10) |
| 5 | `node/consensus_driver.rs` compact→full loopback | **FAIL** — the loopback is not indistinguishable (no `src`, bypasses `INBOUND_DEFERRED_CAP`, lands at the back of a sorted queue). It can be starved and can grow without bound; and the *unverified* `FetchFull` arm plants a permanent `peer_hint` that disables catch-up (R2, R3) |
| 6 | Test updates weakened? | **PASS** — no assertion removed without a stronger replacement; the only "relaxed" expectations are gates that genuinely flipped, and each keeps a below-gate/negative assertion. The zkML and faucet changes are *strengthened* |

Ranked regressions: **R1…R11 in §8**.

---

## 1. Method and environment

* `git diff --stat 3f4b80e16..24e2a1dca` → 44 files, 9 899 insertions.
* Full `git diff` read for: `state_engine/apply.rs`, `governance.rs`, `mempool.rs`,
  `network.rs`, `node/consensus_driver.rs`, `node/policy.rs`, `node/sync.rs`,
  `consensus_net.rs`, `compact_prop.rs`, `xshard2pc.rs`, `xshard.rs`, `svm.rs`,
  `runtime/mev_sync.rs`, `evm_adapter/*`, `rpc/eth.rs`, `explorer.rs`, all test files.
* Targeted tests run (all green, no code changed):

```text
cargo test --test catch_up_tests backstop_interval_default_is_thirty_seconds   -> ok
cargo test --lib gov_ops_pre_activation_refuses_and_moves_nothing              -> ok
cargo test --lib xpc_commit_credit_is_counted_once_and_replay_does_not_count   -> ok
cargo test --test compact_gossip_tests compact_gate_is_active_from_genesis_and_below_gate_refuses -> ok
cargo test --test faucet_turnstile_tests unconfigured_loopback_still_dispenses -> ok
```

The tests confirm the *new* assertions, not the absence of the regressions below.
In particular, the governance tests call `apply_block_transition(block, 0)`
(`stellereum/tests/gov_ops_onchain_tests.rs:77`) and therefore never exercise the
runtime reward resolution that R1 is about.

---

## 2. Item 1 — changed defaults and gates

### 2.1 What changed (all in the reviewed commit)

| Gate / knob | Old | New | Declared at |
|---|---|---|---|
| `CATCHUP_INTERVAL_DEFAULT_MS` | 2 000 | **30 000** | `stellereum/src/node/policy.rs:37` |
| `CATCHUP_BUDGET_DEFAULT_MS` | (inline 250) | **250** (named) | `stellereum/src/node/policy.rs:49` |
| `STELL_CATCHUP_INTERVAL_MS` | honored | **still honored** (`.filter(>0)`, default 30 s) | `stellereum/src/node/policy.rs:429-437` |
| `STELL_CATCHUP_BUDGET_MS` | honored | **still honored** (`.filter(>0)`, default 250) | `stellereum/src/node/policy.rs:442-450` |
| `LIVE_ADOPT_FRESH_MS` (new) | interval (2 s) | **2 000** (deliberately ≠ new interval) | `stellereum/src/node/policy.rs:55` |
| `GOV_OPS_ACTIVATION_HEIGHT` | `u64::MAX` | **0** | `stellereum/src/governance.rs:151` |
| `XPC_ACTIVATION_HEIGHT` | `u64::MAX` | **0** | `stellereum/src/xshard2pc.rs:146` |
| `COMPACT_GOSSIP_ACTIVATION_HEIGHT` | `u64::MAX` | **0** | `stellereum/src/consensus_net.rs:2097` |

Internal consistency is good:

* `XpcActivation::from_chain_spec()` returns `FromHeight(0)`, `Default` delegates to it
  (`xshard2pc.rs:315-345`), `chain_spec.rs:170-177` registers it and the chain-spec test
  now pins `ActiveFromGenesis` / `Some(0)` (`chain_spec.rs:334-350`).
* `GOV_OPS` is a plain compile-time constant, **not** an env knob
  (`governance.rs:127-151`), which is the right pattern for a consensus gate.
* `COMPACT_GOSSIP` uses `>=` plus an explicit `u64::MAX` sentinel exclusion
  (`consensus_net.rs:2112-2145`), and the same predicate is used by emitter,
  decoder (`check_compact_gate`, `:563-586`) and receiver (`open_compact_proposal`, `:2351`).
* The new 30 s backstop has a dedicated pin
  (`stellereum/tests/catch_up_tests.rs:637-642`) and the freeze table was updated
  (`stellereum/tests/freeze_pins_tests.rs:52`).

### 2.2 Gates that are *not* consistent

`GOV_OPS_ACTIVATION_HEIGHT` is now an **active, genesis-on consensus gate that is
invisible to the operator-facing schedule**: `chain_spec::current_activation_schedule()`
still lists exactly 7 gates and `GOV_OPS` is not among them
(`stellereum/src/chain_spec.rs:137-180`; the count is pinned by
`chain_spec.rs:262-272`). `UPGRADE_EXEC_ACTIVATION_HEIGHT` is also absent, but that is
pre-existing. The difference is that `GOV_OPS` now **does something**, so "not in the
schedule" is no longer harmless.

### 2.3 Pins that still assert the OLD value (reviewed commit `24e2a1dca`)

| Pin | What it still says | Reality |
|---|---|---|
| `stellereum/docs/CONSENSUS_SYNC.md:46` | "default 2000ms … (`src/main.rs:40-43,…`)" | 30 000 ms, `node/policy.rs:37`; `src/main.rs` no longer exists |
| `stellereum/docs/CONSENSUS_SYNC.md:52` | budget 250 ms | still true, but the same paragraph still describes the old poll semantics |
| `docs/UPGRADE_AND_RECOVERY.md:21` | `GOV_OPS_ACTIVATION_HEIGHT` "frozen at `u64::MAX`" | `0` |
| `docs/UPGRADE_AND_RECOVERY.md:74,93` | "`u64::MAX`", "Not in `chain_spec`; blocks all multi-node governance" | `0`; "not in chain_spec" is still true but the second clause is false |
| `docs/COMPLETENESS_GAP_ANALYSIS.md:33,57` (and `127`, `512` "schedule is incomplete") | governance scan "gated off"; `GOV_OPS` still listed under the `u64::MAX` constants; `chain_spec` omission is called a gap | `0`; the omission is now material |
| `docs/REVIEW_QUALITY.md:178` | `GOV_OPS_ACTIVATION_HEIGHT` = `u64::MAX` | `0` |
| `docs/REVIEW_STATE_ECONOMICS.md:299` | reward-from-local-state is "safe **only because** governance is inert" | no longer safe → see R1. *(The dirty tree already reclassifies this to P1; that edit is WIP, not in the range.)* |
| `stellereum/PROTOCOL.md:512-524` | `STELL_XPC_ACTIVATION_HEIGHT=<h>` arms 2PC; "default is **off** (legacy)" | env is **deprecated and ignored** (`node/policy.rs:1020-1047`); gate is `0` from genesis |
| `stellereum/docs/program/specs/01_ARCHITECTURE_OVERVIEW.md:39` | "2PC gated by `STELL_XPC_ACTIVATION_HEIGHT` (OFF)" | as above |
| `stellereum/docs/program/specs/03_VM_AND_EXECUTION.md:30` | "`STELL_XPC_ACTIVATION_HEIGHT` (currently OFF everywhere)" | as above |
| `stellereum/docs/program/WORKCHAIN_DECISION.md:43,132,168` | env → `XpcActivation::Disabled`; "leave unset (legacy flow)" | env ignored; 2PC on |
| `stellereum/docs/SHARDING.md:606` | `STELL_XPC_ACTIVATION_HEIGHT=4200` example | no effect |
| `scripts/local-cluster.md:14,46,93,110` and `scripts/local-cluster.sh:26,41,173` | 2-shard mode is enabled by `STELL_XPC_ACTIVATION_HEIGHT=5`; single-shard is `Disabled` | env is ignored with a WARN; 2PC is on everywhere. The script's FATAL check still passes only because the node now logs "2PC ACTIVE from height 0" regardless (`consensus_driver.rs:317`) |

The **root `docs/`** copies of these specs were updated in the range
(`docs/specs/01_ARCHITECTURE_OVERVIEW.md:39`, `docs/specs/03_VM_AND_EXECUTION.md:30`,
`docs/specs/04_NETWORK_AND_CONSENSUS.md:40,64`, `docs/site/07-glossary.md:34`), but the
`stellereum/docs/program/**` mirror and `stellereum/PROTOCOL.md` were not. That split is
exactly the kind of drift that makes an operator follow a dead knob.

**Item 1 verdict: FAIL.** The constants themselves agree; the *pins* do not.
Minimal fix: update the table rows above to the new values (or delete the rows), and
register `GOV_OPS_ACTIVATION_HEIGHT` in `chain_spec` so the active gate is visible.

### 2.4 Env still honored?

* `STELL_CATCHUP_INTERVAL_MS`: yes (`policy.rs:429-437`), and `0`/garbage falls back to
  30 s rather than disabling. Same as before.
* `STELL_CATCHUP_BUDGET_MS`: yes (`policy.rs:442-450`), default 250.
* `STELL_XPC_ACTIVATION_HEIGHT`: **deliberately ignored** (WARN once). This is defensible
  (a per-node consensus switch is a fork knob) but it makes every doc that tells the
  operator to set it wrong — see the table.

---

## 3. Item 2 — `state_engine/apply.rs` step 5e

### 3.1 Ordering (PASS)

The block transition order is now:

```
1  txs → 1a xpc prepares → 1b actor mailbox
2  fees → 3 reward → 4 unbonding
5  downtime slash → 5b equivocation → 5c gov propose/vote
5d CN-VRF v3 → 5e governance finalize+execute
```

Evidence: `stellereum/src/state_engine/apply.rs:2626-2875`
(5c `:2850`, 5d `:2852-2862`, 5e `:2873`).

5e is **last**, so it cannot change the inputs of any earlier domain in the same block:

* it takes `governance_write` **before** `staking_write`, then drops staking, then
  optionally `oracle_write` (`apply.rs:4430-4452`). That is the same order as
  `apply_gov_ops` (`:4306-4308`) and as the RPC/live sweep
  (`runtime/apply.rs:47-48`), so no lock cycle.
* parameters it writes (`SetMinGasLimit`, `SetBlockReward`, `SetMinValidatorBond`,
  `SetPquorum…`) are consumed by later blocks, never by an earlier step of *this* block.
* `finalize_due_at_height` schedules `cur_height + GOV_TIMELOCK_HEIGHTS` (7 200,
  `governance.rs:60,1698`), so a proposal that *passes* in 5e cannot also *execute* in 5e.

### 3.2 `has_due_governance` cannot skip work `execute_due_governance_at_height` would do (PASS)

Filter-by-filter:

| Set | `has_due_governance` (`governance.rs:2116-2128`) | `due_governance_ids` (`:2089-2110`) |
|---|---|---|
| finalize | `Open && now >= voting_end` | not its job (finalizer runs first) |
| execute | `Passed && is_mature && (upgrades || !upgrade_action)` | **identical** |

`is_mature` accepts `Passed` *and* `Executed` (`:1808-1818`), but both call sites also
require `status == Passed`, so an already-executed proposal is not re-run. The
finalizer uses the same `(now, cur_height)` the fast path used
(`finalize_due_at_height`, `:2138-2172`), and is idempotent on terminal status
(`finalize_inner` returns early, `:1675-1677`). The upgrade-only arm remains gated by
`upgrade_exec_active_at` in both places, so a matured `SoftwareUpgrade` never causes a
lock/generation bump while `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX`.

There is now **duplicate finalization** on the live path: 5e finalizes inside the
apply and `sweep_gov_finalize` finalizes again after the apply
(`runtime/apply.rs:515,740,1069,1148`). It is idempotent (same height, same
`block.timestamp`, status moves once), so this is waste, not a regression.

### 3.3 The system-level failure (FAIL): activating 5e makes DET-01 reachable

`execute_due_governance_at_height` now executes **every** `GovAction`, not just upgrades
(`governance.rs:2182-2230`; the old `other => Err` arm is gone). `SetBlockReward`
writes `applied.block_reward` immediately and unconditionally
(`governance.rs:2320-2326`, bound at `:428-432`). That is committed state and it is
correct per-node.

But the **proposer reward is not taken from the block or from the committed pre-state**
of the apply. It is resolved by each node *before* calling the transition, from a
node-local copy of governance:

```
runtime/apply.rs:213   let reward = block_reward_for(...);   // apply_decided (finalize)
runtime/apply.rs:798   let reward = block_reward_for(...);   // try_finalize_submit (sequenced)
runtime/apply.rs:1144  apply_and_advance -> apply_block_fees_rewards (adopt / walk / catch-up)
runtime/cluster.rs:383 let reward = block_reward_for(...);   // ChainState::apply_block (reorg)
runtime/lanes.rs:125   gov.and_then(|g| g.applied.block_reward).unwrap_or(default)
```

`self.governance` is refreshed **once per consensus tick** from the shared state-engine
governance (`node/consensus_driver.rs:1571-1573`), not per applied block. Therefore:

* a live node applies block H, executes `SetBlockReward` at 5e, and uses the new value
  from the next tick onward;
* a node that applies H…H+N in a **single catch-up / walk burst**
  (`apply_and_advance`, `runtime/apply.rs:1125-1148`) uses the **old** value for every
  block in the burst;
* a node that restores a snapshot at height ≥ H seeds `rt.governance` from storage
  (`consensus_driver.rs:397-402`) and therefore uses the **new** value.

Same block, different mint → different state root. This is exactly the failure
`docs/REVIEW_STATE_ECONOMICS.md:299` predicted ("the moment governance activates …
forks the root") and `docs/COMPLETENESS_GAP_ANALYSIS.md` did not close. The wave
activates it at genesis. The existing governance path test passes only because it
calls `apply_block_transition(&block, 0)` and never goes through `apply_decided`
(`stellereum/tests/gov_ops_onchain_tests.rs:77,224-240`). See **R1**.

**Item 2 verdict: PASS for the specific ordering / skip questions, FAIL as a
regression gate because the step it enables is unsafe end-to-end.**

---

## 4. Item 3 — `mempool.rs` carrier branch

### 4.1 Does it shadow or weaken PQ1/SF1 admission? (PASS)

* The EV1 refusal (`mempool.rs:1993-1997`), the PQ1 envelope/scheme gate
  (`:2001-2011`), the wire/proof caps (`:2020-2048`) and the shard gates
  (`:2050-2064`) all run **before** the new call at `:2066`.
* `check_evm_payload` (`:2465-2559`) starts with
  `let Some(payload) = classify_evm_payload(tx) else { return Ok(None) }`, so it is a
  strict no-op for every non-EVM transaction, including all PQ1 and SF1 txs.
* It only *adds* errors (`:2474-2478 Mixed`, `:2481-2500 Binding`, `:2504-2556 Carrier`);
  no branch clears or downgrades an earlier rejection.
* The only behavioural side effect is error *ordering* for an EVM payload that is also
  out of session scope: the carrier error is reported before `check_session_policy`
  (`:2069`). Cosmetic.

### 4.2 Overflow / underflow (PASS)

All arithmetic on the new paths is saturating or checked:

* `surcharges_for_tx`: `activation.saturating_add(carrier)` (`mempool.rs:907-922`);
* `tx_cost`: `amount.saturating_add(gas_limit).saturating_add(...)` (`:931-937`);
* `effective_floor_for_tx`: `base.saturating_add(activation).saturating_add(carrier)`
  (`:1122-1135`);
* `sponsor_fee_cost`: `.max(...).saturating_add(...)` (`:954-960`);
* engine side already uses `checked_add` with an explicit overflow refusal
  (`state_engine/apply.rs:1329-1335`).

### 4.3 The fee arithmetic is still wrong at execution (FAIL)

Admission/`tx_cost`/packing treat the carrier surcharge as an additive charge, but the
**execution fee formula never adds it**:

```
state_engine/apply.rs:1605-1620  floor_parts_for -> surcharge = if is_pq_activation { PQ } else { 0 }
state_engine/apply.rs:1542-1568  consensus_floor_parts -> same
state_engine/apply.rs:1675-1684  fee_for_gas = max(billed, floor_base) + surcharge
```

`EVM_CARRIER_SURCHARGE_GAS = 30_000` (`mempool.rs:26-37`) is therefore a *declaration
floor* only: it forces `gas_limit` (and the sender's reserved balance) up, but the actual
fee is `max(billed_gas, governed+penalty) + PQ_surcharge`. A carrier's measured opcode
gas is ~7 000 (`svm.rs:310-330`: 2 000 base + ~4 690 PQ verify + 2/byte of EVM tx), and
`governed_base` is 0 on a chain that has not raised `min_gas_limit`. So a carrier can be
included by a Byzantine proposer at ~7 000 nano where admission demanded
`280 000 + 30 000`. Deterministic (no fork), but it is a spam/underpricing hole and it
contradicts the "single definition / all consumers price the same" comment at
`mempool.rs:899-906`.

The same applies to the **nonce/value equality**: `facts.nonce == tx.nonce` and
`facts.value_nano == tx.amount` are checked only in `check_evm_payload`
(`mempool.rs:2513-2534`). `validate_proposal_*` does not call `check_evm_payload`
(`runtime/consensus_step.rs:775-806` only checks order/sigs/floors/header), and the SVM
arm re-verifies the intent but not those two equalities (`svm.rs:2540-2572`). A
Byzantine proposer can therefore include a carrier whose EVM intent and Stell leg
describe different payments; every node executes it identically (no fork), but the
EVM-facing receipt then settles an intent that the Stell leg does not match. See **R7**.

**Item 3 verdict: PASS on shadowing/PQ1/SF1 and overflow; FAIL on fee semantics.**

---

## 5. Item 4 — `network.rs` validator mesh + fallback

### 5.1 Cannot double-send in production (PASS — because it never sends)

`deliver_consensus_mesh` (`stellereum/src/network.rs:1271-1273`) has **no production
caller**: `rg 'deliver_consensus_mesh'` finds only its definition and
`stellereum/tests/validator_mesh_tests.rs`. The only production activity is the
heartbeat loop spawned in `P2pNetworkAdapter::new` (`network.rs:1167-1188`), which calls
`maintain()` (`:889`) and therefore `probe()` only. No consensus frame travels the
direct path today. So the mesh cannot double-send; it also adds no propagation benefit
(see **R10**).

### 5.2 If it *were* wired, the fallback duplicates (by design)

`ValidatorMesh::deliver` sends to every direct target, then:

```
network.rs:869-880
if delivery.direct_failed > 0 || delivery.direct_ok == 0 {
    fallback_used = true;
    fallback_ok   = publish_overlay(topic, data) ...   // WHOLE message, broadcast
}
```

The overlay publish is a broadcast to the whole overlay, so every peer that already
received the direct copy gets a second copy. It is not "retry the failed copies"; it is
"retry the message". The comment says "any failed copy … handed to the fallback ONCE",
which is accurate about the *count* but not about the *audience*.

### 5.3 Duplicate delivery is idempotent at the receiver (PASS)

Verified per message kind:

* **Votes** — `VoteSet::add` is keyed by voter and returns before touching `power` when
  the same vote is seen again; a different vote for the same height is recorded as
  equivocation evidence at most once per pair (`stellereum/src/consensus/engine.rs:591`,
  with the early-return above it). Duplicate delivery cannot inflate a QC.
* **Proposals** — the full path verifies the proposer signature and re-checks
  height/round/root (`runtime/consensus_step.rs:1100-1130`); a second copy after
  acceptance is refused by the height/round/`has_live_proposal` guards. The compact path
  re-resolves and pushes a second loopback, but the loopback full path refuses it the
  same way.
* **Committed** — adoption requires `height == hc.height`
  (`runtime/consensus_step.rs:2122-2126`); once adopted, `hc.height` advanced, so the
  copy is ignored. A duplicate *ahead* commit only re-sets `catchup_pending` (idempotent).
* **Compact** — duplicate `CompactProposal` re-resolves; the `attempts` counter bounds
  pulls, and a completed resolution only costs a loopback (see R3 for that cost).

So the answer to the specific worry — "could duplicate delivery change vote counts?" —
is **no**, provided the receiver de-duplication above is not weakened. It is not.

**Item 4 verdict: PASS for vote-count safety; the mesh is inert today. The fallback
design is a latent N² fan-out if wired (R10).**

---

## 6. Item 5 — `node/consensus_driver.rs` compact→full loopback

### 6.1 Is the injected proposal indistinguishable from a wire proposal? (FAIL)

The loopback is a JSON `{"data": hex}` string (`consensus_driver.rs:18-36`) pushed into
`inbound_deferred` (`:1166-1170`). Consumers that *do* see a normal proposal: `parse_incoming`
(`consensus_net.rs:2047-2052`), the full proposal arm, attribution, H+1 deferral,
`on_proposal`, vote. Those agree.

Consumers that do **not** agree:

| Consumer | Wire frame | Loopback |
|---|---|---|
| `inbound_peer_key` (`consensus_net.rs:5846-5873`) | infnode injects `"src"` (`infnode/crates/infnode/src/node.rs:3382`) → per-peer bucket | no `src` → `INBOUND_BROADCAST_PEER_KEY` (shared bucket) |
| `admit_inbound` (`consensus_net.rs:6008-6025`) | charged to the sender | charged to the shared broadcast bucket, **after** the compact frame already charged the sender |
| `INBOUND_DEFERRED_CAP` (1 024, `node/policy.rs:687`) | enforced at insert (`consensus_driver.rs:2176,2373,2504`) | **not enforced** — raw `push_back` at `:1168` |
| Sorted `wake_at` invariant (`:2176-2183`) | insert keeps ascending order | `push_back(now)` appends a due item **behind future-dated items** |

So it is indistinguishable for *verification* and *semantics*, but not for
*admission accounting* and *scheduling*.

### 6.2 Starvation (FAIL)

The drain pops only the **front** of `inbound_deferred`, and only if it is due
(`consensus_driver.rs:2112-2125`). Because the loopback is appended at the back with
`wake_at = now` while every other entry is future-dated, it sits behind up to 1 024
entries. New deferrals are inserted in sorted position, i.e. **before** the loopback
(their `wake_at` > now), so under a sustained flood the loopback never reaches the
front. Even without a flood it waits for the front's `wait_ms` (clamped at 5 000 ms,
`consensus_net.rs:5674-5676`) per batch — far past a round timeout.

The loopback is then re-admitted through the bulk limiter. A full block proposal is
`inbound_is_critical == false` (only `Committed` bypasses, `consensus_net.rs:5749-5751`),
and the default bucket is 1 MiB burst / 512 KiB/s (`:5669-5714`). A 24 MiB proposal needs
tens of seconds of tokens (`admit_inbound` is charged `raw.len()`, the hex length ≈ 2× the
block bytes; default 512 KiB/s, 1 MiB burst, re-deferred in 5 s slices). So the compact
path re-creates the
exact receive-side latency it was meant to avoid, and for an honest large block it can
miss the round entirely. On top of that, the loopback push is uncapped: a pinned peer
can send small compact frames that each resolve (against the victim's own mempool) to a
multi-MB block, and every one adds an uncapped queue entry that is re-deferred
repeatedly (see **R3**).

### 6.3 The bigger liveness bug in the same arm: unverified `FetchFull` hint (FAIL)

`FetchFull` is produced when a compact announcement names more than
`COMPACT_PULL_MAX_IDS` (64) missing ids (`compact_prop.rs:869-873`). The announcement is
**unauthenticated**: `open_compact_proposal` checks only the gate and structural bounds
(`consensus_net.rs:2351-2358`); `CompactProposal::validate` never checks a signature
(`compact_prop.rs:634-681`); the proposer signature can only be checked after the body is
resolved because it covers the full block. The `FetchFull` arm then does:

```
consensus_driver.rs:1193-1208
if height > rt.hc.height {
    let hint = (height.saturating_sub(1), block_hash);
    if rt.peer_hint.map(|(h, _)| h < hint.0).unwrap_or(true) { rt.peer_hint = Some(hint); }
    catchup_pending = true;
    peer_named_height = peer_named_height.max(height.saturating_sub(1));
}
```

No `proposal_hint_admissible` / signature / membership check — unlike every other hint
site, which was deliberately hardened in this same wave
(`consensus_driver.rs:2352-2366,2390-2400`; `runtime/consensus_step.rs:1116-1123`).
`rt.peer_hint` is only ever replaced by a **higher** hint and is never cleared, and
`should_probe_dht_head` then returns `false` for any hint above our tip
(`node/policy.rs:155-157`), so `try_catch_up` stops reading the DHT head and walks to
the attacker's hash (`node/sync.rs:584-592`). The absurd-hint guard
(`node/sync.rs:664-667`, > 1 000 000 heights ahead) only *returns*; it does not clear
the hint, so the DHT read stays suppressed on the next pass. A fake hint just one height
ahead is enough. A node at the tip that keeps receiving live commits can eventually
replace the hint with a higher, verified one; a **restarted, far-behind, or one-way
inbound** node (the exact case catch-up exists for) cannot, and stays unable to walk.
`CompactProposal.validate` only rejects `height == u64::MAX` via `compact_gossip_admits`
(`consensus_net.rs:2130-2145`), so any other height is admissible.

**Item 5 verdict: FAIL.**

---

## 7. Item 6 — were the test updates weakened?

**PASS. No test was weakened.** I checked every modified test file and every removed
assertion in `git diff 3f4b80e16..24e2a1dca`. The only removed assertions are gates that
genuinely flipped, and each replacement keeps the below-gate / negative case.

* **Gate flips (equivalent strength).**
  `stellereum/src/chain_spec.rs:334-350`: `GatedOff` → `ActiveFromGenesis`; still asserts
  the boundary and the switch identity.
  `stellereum/tests/xshard_2pc_tests.rs:1258-1280`: `u64::MAX/Disabled` → `0/FromHeight(0)`;
  still asserts `boundary() == Some(0)`, `is_active_at(0)`, and that explicit `Disabled`
  stays off at 0 and `u64::MAX`.
  `stellereum/tests/compact_gossip_tests.rs` (`compact_gate_is_off_until_the_const_is_flipped`
  → `compact_gate_is_active_from_genesis_and_below_gate_refuses`): still drives the
  **below-gate** path through `with_compact_gossip_gate(1_000, …)` and still asserts
  `decode` refuses the sentinel height. The renamed test body is a superset of the old one.
* **`pentest_network_wave.rs`**: renamed
  `attack5_compact_gossip_is_refused_while_the_gate_is_off` →
  `attack5_compact_gossip_gate_is_fail_closed_at_its_boundary`; the old "gate off" assertion
  is retained inside `with_compact_gossip_gate(101, …)`, plus the sentinel refusal. Not
  weakened.
* **`gov_ops.rs` pre-activation test**: this one *looks* like a weakening because the gate
  is now `0`, but it installs a **thread-local** `u64::MAX` override
  (`ClosedGovGate`, `stellereum/src/state_engine/tests/gov_ops.rs:405-430`) and keeps the
  "moves nothing / byte-identical root" assertions. It also still asserts
  `GOV_OPS_ACTIVATION_HEIGHT == 0`. Good.
* **`audit_closure_privacy_tests.rs` (zkML)**: the old assertion "second write is `Err`" is
  replaced with "byte-identical re-registration is `Ok(same hash)`" **plus** a new
  assertion that different weights under a taken id are still refused
  (`:202-224`). The source already had the idempotent fast path
  (`stellereum/src/zkml.rs:1724-1728`); the test was stale, and the update is net
  stronger.
* **`faucet_turnstile_tests.rs`**: the old test asserted a forwarded loopback claim
  mints (`200` + `pending`). The new test asserts `503` **and** `!body.contains("pending")`
  **and** `mock.calls == 0` (`:598-617`). Strictly stronger. (The source fix is
  pre-range: `client_ip.rs` last touched at `0b7280af6`.)
* **New tests** (`catch_up_tests.rs`, `catchup_storm_regression_tests.rs`,
  `partition_heal_tests.rs`, `validator_mesh_tests.rs`, `evm_carrier_binding_tests.rs`,
  `gov_ops_onchain_tests.rs`, `cli_seal_tests.rs`, `peer_eviction_tests.rs`) only add
  coverage. `freeze_pins_tests.rs:52` was updated to 250/30000. No `#[ignore]` was added
  anywhere in the diff.

One caveat (not a weakening): the new policy tests `#[path]`-include
`src/node/policy.rs`, so they pin the *pure* predicate but not the driver wiring. That is
why the `FetchFull` hint bug (R2) and the loopback (R3) are untested.

---

## 8. Ranked regressions and risks

Each item: **what**, **evidence**, **why it matters**, **minimal fix**.

### R1 — **P0 / safety**: `SetBlockReward` executes at 5e, but the reward is resolved per node from a tick-cached governance copy → divergent roots on catch-up

* **Evidence**: `governance.rs:2320-2326` (immediate `applied.block_reward`);
  `apply.rs:2873,2182` (executes every action at genesis);
  `runtime/apply.rs:213,798` (finalize/sequenced reward),
  `:1125-1144` (adopt/walk reward), `runtime/cluster.rs:383` (reorg),
  `runtime/lanes.rs:125-127`; `node/consensus_driver.rs:1571-1573` (refresh once per
  tick, not per block), `:397-402` (restore seeds a different copy).
  `docs/REVIEW_STATE_ECONOMICS.md:299` predicted it; the dirty tree now reclassifies it
  to P1.
* **Why**: a `SetBlockReward` executed at block H is committed, but the *mint amount* for
  H+1 is supplied by the caller from a local copy. Live node (new value) vs catch-up walk
  (old value) vs restarted node (new value) mint different amounts → different state
  root. A walking node then fails its own root check and cannot rejoin; a node that
  proposes during the window forks.
* **Minimal fix**: derive the reward inside `apply_block_transition` from the committed
  governance pre-state at `block.height` (the parameter is the problem, not the
  action), or at minimum re-read `governance_read().applied.block_reward` per applied
  block instead of per tick, on every path (`apply_decided`, `apply_and_advance`,
  `ChainState::apply_block`). Add a regression test that applies H and H+1 through
  `apply_and_advance` after a block-carried `SetBlockReward`.

### R2 — **P0 / liveness**: an unauthenticated compact announcement can plant a permanent `peer_hint` and disable catch-up

* **Evidence**: `compact_prop.rs:869-873` (`TooManyMissing` → `FullProposal`),
  `:634-681` (no signature in `validate`), `consensus_net.rs:2351-2358` (gate only);
  `consensus_driver.rs:1193-1208` (hint planted with no `proposal_hint_admissible`);
  `node/policy.rs:155-157` (`should_probe_dht_head` false when the hint is ahead);
  `node/sync.rs:584-592` (skips the DHT read); `peer_hint` replaced only by a higher hint
  (`consensus_driver.rs:1205,2395,2676`).
* **Why**: a pinned peer (a Byzantine validator is in scope) sends
  `CompactProposal { height: u64::MAX-1, 65 unknown ids }`. It is structurally valid,
  resolves to `FetchFull`, and permanently points the catch-up at a fake head. A behind
  or restarted node can no longer walk the DHT. This directly contradicts the wave's own
  "verified evidence only" invariant used for every other hint.
* **Minimal fix**: do not plant `peer_hint`/`peer_named_height` from `FetchFull` unless
  the announcement is authenticated (add a signature over the compact header to the
  format, or require the resolved block). Scheduling a *bounded* catch-up is fine; a
  persistent hint is not. Additionally clamp any hint to `our_tip + MAX_WALK_GAP` and
  clear it after a failed walk.

### R3 — **P1 / DoS + liveness**: the compact→full loopback bypasses `INBOUND_DEFERRED_CAP`, breaks the queue's sort invariant, and is re-charged to the bulk limiter

* **Evidence**: `consensus_driver.rs:1168` (uncapped `push_back(now)`),
  `:861-863` (queue is meant to be bounded), `:2112-2125` (front-only pop),
  `:2176-2183` (sorted insert for normal deferrals);
  `consensus_net.rs:5669-5714` (1 MiB burst / 512 KiB/s), `:5749-5751` (only `Committed`
  is critical); `mempool.rs:807` (24 MiB block cap) vs
  `compact_prop.rs:321` (32 MiB frame cap), `:712-718` (index built per frame),
  `mempool.rs:3117-3119` (`all()` clones the whole pool).
* **Why**: (a) an honest multi-MB proposal is re-materialized locally, then deferred by
  the limiter for tens of seconds, so the compact path still misses the round; (b) a pinned peer can
  send many small, fully-resolving announcements (the header salt is attacker-chosen and
  the short ids are computed over public mempool txs), each adding an uncapped
  multi-MB queue entry; (c) the loopback sits behind every future-dated entry and is
  starved under a flood. The `on_proposal` call itself also clones the whole mempool and
  rebuilds a salted index **before any authentication** (`consensus_driver.rs:2282-2285`
  → `consensus_net.rs:2498-2522`), so each 400 B frame costs O(mempool) CPU/memory.
* **Minimal fix**: (1) enqueue the loopback through the same capped, sorted insert
  (`if len < CAP` + `insert` by `wake_at`), (2) mark it as already-budgeted/local so
  `admit_inbound` does not defer it (or bypass the limiter for loopbacks), (3) bound/dedupe
  the number of outstanding loopbacks per `(height, round, hash)`, (4) authenticate or
  cheaply pre-filter a compact announcement (height/round window) before cloning the
  mempool and building the index.

### R4 — **P1 / upgrade compatibility**: proposals now gossip *only* compact; pre-wave binaries silently drop every proposal

* **Evidence**: `consensus_driver.rs:1954,3724` (`proposal_gossip_msg` for every
  proposal); `consensus_net.rs:2379-2385` (compact unless compression fails); the three
  new variants are appended after `Batch` (`consensus_net.rs:327-335`), so an old
  bincode decoder rejects the frame and `parse_incoming` returns `None`
  (`consensus_net.rs:2047-2052`). There is no capability negotiation (`rg capab` → only
  a comment).
* **Why**: during a rolling upgrade, an old node cannot decode a compact proposal, so it
  never votes on a round proposed by a new node. New nodes still decode full proposals,
  so old-proposer rounds finish. Liveness is roughly halved at one old node and degrades
  with each old node; if the old set holds ≥1/3 power, enough rounds stall to matter.
  `docs/TWO_SHARD_DEPLOY.md` advertises a roll-forward story that this contradicts (it
  covers XPC records only).
* **Minimal fix**: emit both forms for one release (the full `Proposal` is already built
  and small enough for thin blocks), or gate compact emission on a peer capability flag
  learned at handshake; at minimum, document that the upgrade must be simultaneous or
  that old nodes are expected to lag.

### R5 — **P1 / DoS**: `BodyPull` is replayable and its `Body` reply is broadcast

* **Evidence**: `consensus_driver.rs:2289-2318` (pull → `compact_server.serve` →
  `enqueue_outbox(Body)` → `flush_outbox`), `consensus_net.rs:2677-2720` (`serve` has no
  served/once set), `:484-510` (pull structural validation only).
* **Why**: a pinned peer sees our compact announcement, then replays a sub-KB pull (≤64
  ids) repeatedly; each replay re-broadcasts up to 64 txs to **every** peer. Amplification
  is tens of × per small pull per peer and unbounded in repetition. Pre-wave these frames were refused
  outright, so this is new attack surface.
* **Minimal fix**: keep a bounded `(block_hash, round, id)` served set (or a per-pull
  attempt/rate cap) so a repeated pull is answered once, and unicast the body to the
  requester rather than broadcasting it.

### R6 — **P2 / economic**: the `EVM_CARRIER_SURCHARGE_GAS` floor is never charged at execution

* **Evidence**: admission/packing include it (`mempool.rs:907-922,931-937,954-960,
  1122-1135`); the consensus/execution floor and fee do **not**
  (`state_engine/apply.rs:1542-1568,1605-1620,1675-1684`); the opcode gas is ~7 000
  (`svm.rs:310-330`).
* **Why**: the surcharge raises the *declared limit* and the reserved balance but not the
  fee. A carrier is billed its measured opcode gas, i.e. roughly the price of a plain
  signature check, despite 1.5 KB of extra Falcon/secp work. It also lets a Byzantine
  proposer include carriers below the advertised floor. Deterministic, so not a fork,
  but a fee leak and spam channel.
* **Minimal fix**: make `surcharge` in `consensus_floor_parts`/`floor_parts_for` come
  from `Mempool::surcharges_for_tx(tx)` (one definition), and add the carrier surcharge
  to the execution fee exactly like the PQ activation surcharge.

### R7 — **P2 / invariant**: the carrier's nonce/value equality is admission-only

* **Evidence**: `mempool.rs:2513-2534` (the only check); `svm.rs:2540-2572` (execution
  verifies only the Falcon/intent, not `facts.nonce == tx.nonce` /
  `facts.value_nano == tx.amount`); block validation does not run `check_evm_payload`
  (`runtime/consensus_step.rs:775-806`).
* **Why**: a proposer can include a carrier whose EVM intent settles a different amount
  or nonce than the Stell leg. Execution is deterministic (no fork), but the EVM receipt
  then describes a payment that did not happen — the exact invariant the mempool comment
  claims is re-checked "at execution".
* **Minimal fix**: re-check the two equalities in the SVM carrier arm (or in
  `validate_proposal_*`), and correct the mempool comment.

### R8 — **P2 / liveness**: the at-tip backstop skip can permanently disable catch-up for a silent node

* **Evidence**: `node/policy.rs:105-116` (`SkipAtTip`), `consensus_driver.rs:1330-1348`
  (skip resets `last_catchup`); `peer_hint`/`peer_named_height` are fed only by inbound
  messages (`consensus_driver.rs:1205,2395,2676`; `consensus_step.rs:1116-1123`), and
  `rt.peer_hint` starts `None` (`runtime/anchors.rs:53`).
* **Why**: "at tip" is inferred from *the absence of evidence*. A node whose inbound
  consensus channel is broken (one-way failure, a dropped subscription, a firewall
  change) has no evidence, so it classifies itself at-tip and never probes the DHT — the
  old 2 s poll was the only blind safety net. It stays stalled until something inbound
  arrives, which is exactly what is broken.
* **Minimal fix**: bound `SkipAtTip` (e.g. force one probe after N consecutive skips /
  every 10 min), or treat "no inbound consensus message for > 2 × interval" as
  not-at-tip.

### R9 — **P3 / docs+ops**: the active-gate inventory is stale and `GOV_OPS` is invisible

* **Evidence**: §2.3 table; `chain_spec.rs:137-180` omits `GOV_OPS`; the gate is now on.
* **Why**: an operator reading `PROTOCOL.md`/`local-cluster.md` will set a dead env and
  believe 2PC is off; an operator inspecting `chain_spec` cannot see that block-carried
  governance is live.
* **Minimal fix**: fix the table rows; add `GOV_OPS_ACTIVATION_HEIGHT` (and, while
  there, `UPGRADE_EXEC`, `SPRT`, `MEV_RESHARE`) to `current_activation_schedule` and its
  count test.

### R10 — **P3 / latent**: the validator mesh is inert, and its fallback would fan out N²

* **Evidence**: `network.rs:1271` has no production caller; `:845-880` broadcasts the
  whole message on any direct failure; heartbeat loop at `:1167-1188`.
* **Why**: today it is dead weight (a 10 s probe loop that dials every pinned peer). If
  wired as documented ("direct links first, DHT/overlay fallback"), every message reaches
  each healthy peer twice plus an overlay flood, and the `MeshDelivery::delivered()`
  truth table (`:539-541`) reports success for an empty mesh even when the fallback
  failed.
* **Minimal fix**: wire `deliver_consensus_mesh` into the actual send path **and** change
  the fallback to per-failed-peer semantics (or accept duplicates explicitly and rely on
  the receiver idempotence, documented); fix `delivered()` for the empty-mesh case.

### R11 — **P3 / upgrade semantics**: `XPC_ACTIVATION_HEIGHT = 0` removes the "pre-activation transfers keep the legacy flow" path on an upgraded chain

* **Evidence**: `xshard2pc.rs:128-146` (constant and its doc), `:327-345`
  (`from_chain_spec`), `runtime/mev_sync.rs:1520-1555` (per-height choice).
* **Why**: for a fresh chain there is no pre-0 height, so the caveat is moot (and the
  repo has no deployed mainnet). For an upgraded chain there is **also** no pre-0 height,
  so every in-flight legacy transfer is re-read as "produced at height ≥ 0" and the
  documented "legacy transfers complete" property is false; the target's XSHARD-01 gate
  refuses the one-way credit anyway, so in-flight value would need a manual recovery.
  The new `docs/TWO_SHARD_DEPLOY.md` correctly says "nothing to set", but the code
  comment still promises the legacy-completion path.
* **Minimal fix**: either document that a chain with in-flight legacy transfers must
  drain them before this binary, or pick a real activation height > the current tip for
  such a chain; correct the `xshard2pc.rs` comment for the `0` case.

---

## 9. Suggested minimal patch order

1. **R1** (consensus safety) — reward from committed pre-state, plus a catch-up test.
2. **R2** (unauthenticated hint) — never plant a persistent hint from `FetchFull`; add a
   regression test with a forged compact frame.
3. **R3** (loopback cap/scheduling) — one small change: capped, sorted insert + skip
   `admit_inbound` for local loopbacks; dedupe by `(height, round, hash)`.
4. **R4** (interop) — dual-emit or capability gate; document the upgrade constraint.
5. **R6/R7** (carrier fee/invariant) — route `surcharges_for_tx` into the execution
   floor; re-check nonce/value at execution.
6. **R8** (silent-node catch-up) — bound `SkipAtTip`.
7. **R5, R9, R10, R11** — hardening/docs.

---

## Appendix A — commands used for evidence

```text
git log --oneline 3f4b80e16..24e2a1dca
git diff --stat 3f4b80e16..24e2a1dca
git diff 3f4b80e16..24e2a1dca -- <file>   (all files listed in §1)
rg -n "CATCHUP_INTERVAL|GOV_OPS_ACTIVATION_HEIGHT|XPC_ACTIVATION_HEIGHT|COMPACT_GOSSIP_ACTIVATION_HEIGHT"
rg -n "apply_block_transition|block_reward_for|peer_hint|inbound_deferred|check_evm_payload|deliver_consensus_mesh"
cargo test ... (5 targeted tests listed in §1, all green)
```

## Appendix B — concurrent, uncommitted work (context only)

While this review ran, other sessions modified (uncommitted) `docs/PENTEST2_NETWORK.md`,
`docs/PENTEST2_API.md`, `docs/REVIEW_STATE_ECONOMICS.md`,
`docs/COMPLETENESS_GAP_ANALYSIS.md`, `docs/UPGRADE_AND_RECOVERY.md`,
`docs/COMPACT_PROPAGATION.md` and added `stellereum/tests/pentest2_*.rs`. Those are not
part of `24e2a1dca` and are not relied on here. Two independently reach the same
conclusions as this report: DET-01/R1 (reclassified to P1 in the dirty
`REVIEW_STATE_ECONOMICS.md`) and the compact/loopback cluster in
`PENTEST2_NETWORK.md` (C1/C2/H1/H2/H5/M1/M6). Treat those files as *corroboration*, not
as inputs; the evidence above is from the reviewed commit only.

## Appendix C — what this review did **not** establish

* No full test suite / clippy / release-build run (memory-constrained host; targeted
  tests only).
* `infnode` peer-ACL behaviour is taken from the code (`config.rs`/`services.rs`) only
  as far as needed for the "pinned peer" precondition; I did not run a live multi-node
  scenario.
* The exact power split at which R4 degrades liveness to a halt depends on the deployed
  validator weights; the qualitative statement (compact-only emission denies old nodes a
  vote) is independent of the weights.
