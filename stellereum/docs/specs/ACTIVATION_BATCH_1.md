# Activation batch 1 — consensus-visible changes that are already coded but INERT

Status: **DRAFT for review** (2026-11-25). Nothing in this batch may be armed by
lowering a constant until every prerequisite below is green on all four
validators.

## Why a batch and not three separate activations

Three independent defects need a **height-gated** switch, because changing them
retroactively would make two nodes disagree about blocks that are already final:

| # | Change | Constant | Why it cannot be a hot patch |
|---|---|---|---|
| A1 | Cap WASM table elements at deploy/execution | `WASM_TABLE_ELEMENTS_CAP_HEIGHT` (`u64::MAX`) | A block deploying `(table 100000000 funcref)` is valid today and OOMs every validator; rejecting it changes block validity, so the rule must flip at one height for everyone |
| A2 | Price Falcon host verification honestly | `FUEL_FALCON512_VERIFY` (currently `2_000`) | Raising the fuel price changes which transactions fit in a block and how much gas they burn |
| A3 | Downtime miss budget vs. tempo | `DOWNTIME_MISS_THRESHOLD` (`42`, frozen) | Jailing is deterministic chain state: mixed thresholds produce **different validator sets** |

A1 already exists in code; A2 and A3 need code + spec. None are armed.

## A1 — WASM table element cap (ready, needs arming)

**Threat**: `store_limits()` bounded memory/pages but not table elements, and
`validate_memory_limits` inspected WASM section 5 (memory) but not section 4
(table). A 200-byte module declaring `(table 100000000 funcref)` made `wasmi`
allocate gigabytes at instantiate time, i.e. remote OOM of all validators from
one deploy transaction.

**Rule**
- Post-activation: a module whose table section declares `min` or `max` above
  `MAX_CONTRACT_TABLE_ELEMENTS` (16 384) is rejected, and the engine is
  configured with `.table_elements(MAX_CONTRACT_TABLE_ELEMENTS)`.
- Pre-activation: byte-identical acceptance to today (verified by the
  pre-activation pin tests in `tests/activation_gate_*`).

**Prerequisites before arming**
1. Green `contract` + `svm` suites with both flag states.
2. An e2e that deploys `(table 1000000 funcref)` *after* activation and sees
   `InvalidWasm`, and the same module *before* activation still deploys.
3. The RPC pre-validation path enforces the cap **immediately** (it is
   node-local, no consensus impact) so mempool junk is filtered early.
4. `stellereum gates --yaml` regenerated; the gate row leaves `INERT`.

## A2 — Falcon host fuel (needs code + spec)

**Threat**: `FUEL_FALCON512_VERIFY = 2_000` against a 50M block budget lets one
transaction request ~24 750 full Falcon-512 verifications (~few ms each), i.e.
seconds of block execution per tx. Second defect: `SysCallDeployContract`
validates the module twice and the `(start)` section runs twice without charging
`state.gas_remaining`.

**Rule**
- Charge the real cost: target `100_000`–`250_000` fuel per verification
  (calibrate against `benches/pq_end_to_end.rs`; pick the value that makes one
  verification ≈ one unit of wall time per the bench, then round up).
- Validate the module **once** per deploy and charge the actual `(start)` fuel
  consumed against the caller's remaining gas.
- Gate all three at `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT`.

**Prerequisites**
1. Bench numbers pasted (one verification cost on a 1-vCPU host and on the
   16-core host; pick the worst case).
2. Differential test: pre-activation gas/fuel for a fixed tx is byte-identical
   to today; post-activation the same tx is either rejected or charged the new
   amount — never "sometimes".
3. A contract-level test that a `(start)` loop cannot run twice.

## A3 — Downtime miss budget (needs a decision + spec)

**Threat**: `DOWNTIME_MISS_THRESHOLD = 42` means 42 consecutive misses. At the
current 400 ms floor that is **16.8 s**, and nodeC (1 vCPU, 68 % CPU from the
node alone) trips it every ~400 blocks. Each trip costs `JAIL_RELEASE_DELAY_HEIGHTS`
= 4000 blocks (~20–25 min) plus a cold-key unjail.

The constant is documented as frozen ("change requires spec update + audit note",
AGENTS.md §7), and the v2 ruleset tuned it for a 240 ms tempo (42 × 240 ms ≈
10 s). We now run at 400 ms, so the *intent* (≈10 s of tolerance) is violated in
the other direction: the wall-clock tolerance grew while the hosts did not.

**Options (pick one in review)**
1. **Keep 42** and fix the hosts (2 vCPU for C/A/D). Cheapest in code: zero.
2. **Efficiency-based jailing**: jail when a validator misses more than X % of
   the slots it owned over a window (TON's `low_efficiency`, Solana's skip
   rate), which is tempo-independent and matches the enterprise expectation.
   Needs: window definition, deterministic evidence in the block, and a
   migration rule for validators jailed under the old rule at the activation
   height.
3. **Raise to 150** (= 60 s at 400 ms) at `JAIL_BUDGET_V2_ACTIVATION_HEIGHT`.
   Simple, but it also makes a genuinely dead validator sit in the set longer.

Recommended: (2) if the enterprise story matters, (3) as an interim step with an
explicit expiry, (1) if the hardware order is already placed.

## Rollout order (all three)

1. Land the code with every new constant at `u64::MAX`; gate green.
2. Publish this spec with the chosen heights; regenerate the gate manifest.
3. Deploy the new binary to **all four** nodes *before* the activation height
   (deploy order C → A → D → B, one at a time, set must be 4/4).
4. Verify each node reports the same `stellereum gates` table (`ACTIVE` after
   the height) and that the heights are identical.
5. Only then cross the height. Rollback after the fact is impossible by design —
   the only remedy is a coordinated restore.

## Invariants that must hold across the whole batch

- No change to: block hash inputs, QC wire bytes, signature domains, quorum
  math, `apply()` semantics for already-valid transactions, staking math.
- A node that misses the activation height must exit or refuse to vote rather
  than guess (fail-closed), and say so loudly at startup.
- The pre-activation behaviour of every item stays pinned by a test that fails
  if someone lowers the constant without updating the test.
