# Activation gates: pinned pre-activation behaviour and arming checklists

Three protocol gates are deliberately INERT (`u64::MAX`) and are tracked as
activation debt by `stellereum/src/feature_gates.rs` (printed by
`stellereum gates`, manifest at `docs/feature_gates.yaml`, pinned to the code by
`feature_gates::tests::committed_manifest_matches_the_table`):

| Gate | Constant | Compiled value | Status |
| --- | --- | --- | --- |
| contract block hash | `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` | `u64::MAX` | INERT |
| bridge target-address cap | `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` | `u64::MAX` | INERT |
| cross-shard bounce escrow | `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` | `u64::MAX` | INERT |

Every gate helper has the same shape: if the effective gate is `u64::MAX`,
`*_active_at(height)` is `false` for **every** height, including `u64::MAX`
itself. The `u64::MAX` sentinel is therefore "never", not "at the last block".

This document records exactly what each gate changes, which invariants must hold
on both sides, and what is still missing before it can be armed. The three test
files named below pin the **inert** side. They are not the post-activation proof
the manifest requires; `test:` must stay `MISSING` until the e2e listed in each
checklist exists.

Run only these pins with:

```sh
cargo test --test activation_gate_contract_block_hash_tests
cargo test --test activation_gate_bridge_target_address_cap_tests
cargo test --test activation_gate_xshard_bounce_escrow_tests
```

All three are deterministic and need no live node or network.

---

## 1. `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT`

Pinned by `stellereum/tests/activation_gate_contract_block_hash_tests.rs`.

### 1.1 Where the gate is consulted

| Place | Role |
| --- | --- |
| `chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` | compiled gate, `u64::MAX` |
| `chain_spec::contract_block_hash_activation_height()` | effective (test/debug override) |
| `chain_spec::contract_block_hash_active_at(h)` | single activation predicate |
| `svm::VmExecOptions::contract_block_hash` | parent hash supplied by the caller |
| `svm::Svm::execute_inner` (`svm.rs`) | substitutes `[0u8; 32]` unless active |
| `contract::ContractCallContext::block_hash` | value the host function writes |
| `contract::link_contract_host_functions` (`host.block_hash`) | charges `FUEL_BLOCK_HASH` (10) and writes 32 bytes to WASM memory; it is **not** itself gated |
| `contract::ContractRegistry::call_with_context` | accepts whatever `block_hash` the caller put in the context; the SVM is the enforcer |
| `state_engine::apply::execute_payload_with_preverify_at_height_and_parent` | public payload entry with an explicit parent |
| `state_engine::apply::apply_block_transition` | live block path: passes `block.prev_hash` down to `apply_block_parallel_fees_with_events_at_height_and_parent` |
| `state_engine::apply::execute_payload_with_preverify[_at_height]`, single-tx `apply_transaction`, RPC preview | no block context: pass `[0u8; 32]` |

### 1.2 Before the gate (today)

- `contract_block_hash_active_at(h)` is `false` at every height.
- `host.block_hash` is **present**, not refused and not absent. It succeeds,
  charges 10 fuel, bounds-checks the destination pointer for 32 bytes, and
  writes exactly `[0u8; 32]`.
- The gate lives in the SVM, not in the host function: a direct
  `ContractRegistry::call_with_context` caller can pass any `block_hash` it
  constructed. Every production execution path goes through the SVM (or the
  zero-default `contracts.call` helper), so consensus contracts see zero.
- The live block path already supplies `block.prev_hash` in
  `VmExecOptions.contract_block_hash`, but `Svm::execute_inner` discards it
  below the gate. A contract cannot distinguish "no block" from a zero hash.
- Callers without a block context (single-tx apply, RPC preview) pass zero even
  with the gate armed, because they have no parent hash to supply.
- Gas accounting, host-function signature and WASM memory layout are unchanged;
  a pre-activation block replayed by the same build produces the same state
  root byte-for-byte.

### 1.3 After the gate (`height >= H`)

- `Svm::execute_inner` passes `opts.contract_block_hash` into
  `ContractCallContext.block_hash`; `host.block_hash` writes it unchanged.
- The value is the **parent** hash (`block.prev_hash`), never the current
  block hash: the current hash commits execution output (`body_commitment`
  includes `cross_shard_out`) and cannot be known before the payloads run.
- The parent is identical on every node applying the same block and across
  repeated executions/reorg re-applies of that block.
- Non-block callers still see zero. That is a deliberate limitation, not a
  second consensus rule, but it must be documented and tested so a preview
  cannot be mistaken for committed behaviour.

### 1.4 Invariants

Before (must remain true while inert):

1. Every contract sees 32 zero bytes on every path that supplies a block context.
2. No state root, wire format, host-function signature, fuel cost or WASM memory
   layout changes.
3. A historical block replayed by the same build yields the same root.

After (must hold at/above `H`):

1. Every transaction in a block sees the same parent hash, on every node.
2. The value is `block.prev_hash`, not `block.compute_hash()`.
3. Re-execution, reorg re-apply, restart replay and the block path
   (`apply_block_transition`/`ChainState::apply_block`) all derive the same
   value from the same block bytes.
4. Contracts are not promised unpredictability: the parent hash is public and
   must not be used as a randomness source.
5. All nodes run the armed build before `H`; a node at the old value would
   execute the same payload differently and fork the state root.

### 1.5 What still blocks activation

1. **No cross-node block-path e2e.** The existing pin and
   `tests/review_final_contract_block_hash.rs` use
   `execute_payload_with_preverify_at_height_and_parent` on one engine. No test
   applies the same block through `apply_block_transition` on two independent
   engines/nodes and compares the contract-observed bytes (or a contract storage
   slot derived from them) and the resulting state root.
2. **No reorg/replay/restart e2e.** `ChainState::apply_block`,
   `apply_block_transition`, snapshot restore and re-org re-apply must all expose
   the same value. This is unproven.
3. **Non-block context policy is unresolved.** Single-tx `apply_transaction` and
   RPC preview pass zero. Decide whether that is acceptable (and test it) or
   thread a block context into those callers. Without a decision, a preview can
   disagree with committed execution.
4. **The manifest note is stale on plumbing.** The consensus block path already
   threads `block.prev_hash`; the blocker is proof (1–3), not a missing
   parameter on that path.
5. **The host function is not the gate.** Audit every `call_with_context`
   caller: production consensus execution must only reach it through the SVM
   (which zeroes the value while inert). A future caller passing its own
   `ContractCallContext.block_hash` would bypass the gate and must not exist on
   a consensus path.
6. **Governance decision.** Exposing a nonzero block identifier is a
   contract-visible semantic change; contracts that treated zero as a sentinel
   may change behaviour.

### 1.6 Checklist to arm

- [ ] Add a post-activation e2e that applies a block via
      `apply_block_transition` on two engines, has a contract observe
      `host.block_hash`, and asserts it equals `block.prev_hash`, differs from
      the current `block.compute_hash()`, and produces the same state root on
      both engines.
- [ ] Extend that e2e to a reorg/re-apply and a snapshot/restart replay.
- [ ] Add the non-block-context test (single-tx / RPC preview), or a written
      decision that those callers intentionally see zero.
- [ ] Audit `ContractRegistry::call_with_context` callers: consensus execution
      must reach the host only through the SVM, so no caller can inject its own
      `block_hash` and bypass the gate.
- [ ] Set `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT = H` in `chain_spec.rs`.
- [ ] Update the `feature_gates.rs` row: point `test:` at the new e2e and correct
      the note (src change outside the pin-only scope).
- [ ] Regenerate `docs/feature_gates.yaml` with `stellereum gates --yaml`
      (`feature_gates::tests::committed_manifest_matches_the_table` fails
      otherwise).
- [ ] Replace the inert pin in `stellereum/tests/activation_gates_inert.rs`
      (and this file's pre-activation assertions) with the post-activation
      expectations.
- [ ] Deploy the armed binary to **all** nodes before `H`, verify
      `current_activation_schedule()` shows the same `H`, then cross the height.
- [ ] Never lower `H` afterwards: blocks below it were executed with zero.

---

## 2. `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT`

Pinned by
`stellereum/tests/activation_gate_bridge_target_address_cap_tests.rs`.

### 2.1 Where the gate is consulted

| Place | Role |
| --- | --- |
| `bridge::MAX_BRIDGE_TARGET_ADDRESS_BYTES` | the cap: 128 UTF-8 bytes |
| `chain_spec::BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` | compiled gate, `u64::MAX` |
| `chain_spec::bridge_target_address_cap_active_at(h)` | single activation predicate |
| `bridge::validate_bridge_target_address_len(addr, h)` | pure gated check |
| `bridge::BridgeIntent::validate_at_height(h)` | Withdraw arm calls the helper |
| `bridge::BridgeIntent::validate()` | delegates to height `0` (VM has no height) |
| `bridge::BridgeState::plan_at_height(...)` | settlement/park path calls the helper |
| `state_engine::settle_bridge_native` | passes the real `block_height` into `plan_at_height` |
| `BridgeIntent::Release` / `BridgeIntent::Refund` | **no** target-length check |

### 2.2 Before the gate (today)

- The only address check is non-empty after `trim()`. Any length is accepted.
- `BridgeState::plan_at_height` parks and commits the address into
  `pending_withdrawals`; the hourly rate limit counts the withdrawn **amount**
  only, so a 1 MiB address costs no bridge value.
- `validate_bridge_target_address_len` is a no-op at every height;
  `validate_at_height` and the height-less `validate()` agree on acceptance.
- A long-target request can be refunded after `unlock_at + REFUND_GRACE_SECS`;
  `Release`/`Refund` never inspect the address length. This is the pre-gate
  state that must stay replayable.
- Historical acceptance verdicts and the committed bridge-state bytes are
  unchanged.

### 2.3 After the gate (`height >= H`)

- A `Withdraw` whose `target_address.len()` is greater than 128 bytes is refused
  **before** the rate window is touched, before the request is parked and before
  any value moves.
- The error names `MAX_BRIDGE_TARGET_ADDRESS_BYTES (128)` and the offending
  length. Exactly 128 bytes is accepted; 129 is refused.
- The rule is height-indexed, so a pre-`H` block replayed by an armed binary
  keeps its historical verdict. Existing long-target requests already in
  `pending_withdrawals` are **not** retroactively rejected by this gate.
- `Release`/`Refund` remain length-agnostic. A long address parked before `H`
  must remain finalizable after `H` unless a separate migration is specified.
- `validate()` (height 0) only enforces the cap if `H == 0`; settlement always
  enforces it at the real height. This is intentional: the VM check is a cheap
  subset and settlement is authoritative.

### 2.4 Invariants

Before (must remain true while inert):

1. `validate_bridge_target_address_len` is a no-op at every height.
2. A 1 MiB (or 129-byte) target is parked byte-for-byte and creates the same
   effects as a normal one.
3. A replayed pre-gate block produces the same bridge state and root.
4. Long-target requests remain refundable/releasable.

After (must hold at/above `H`):

1. All nodes use the same `H`; the verdict is a pure function of
   `(target_address bytes, height)`.
2. The refusal happens before any rate-window, queue or account write.
3. The measurement is Rust `str::len()`, i.e. **UTF-8 bytes**, not characters;
   multi-byte addresses must be tested at the 128/129-byte boundary.
4. No wire/transaction/block format changes; only the settlement verdict changes.
5. Pre-gate parked long requests are handled by a stated policy (kept
   releasable/refundable, or migrated) and that policy is tested.

### 2.5 What still blocks activation

1. **The gate is absent from `current_activation_schedule()`.** The other two
   gates in this document are listed there; `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT`
   is not, so operators cannot see its scheduled height through the schedule
   surface.
2. **No gate-specific block-path e2e.** `tests/h9_bridge_target_address_cap.rs`
   drives `plan_at_height`/`validate_at_height`; the existing block-path bridge
   tests (`bridge_onchain_tests.rs`, `bridge_persistence_tests.rs`, …) use normal
   addresses below the inert gate. No test builds a payload with an over-long
   target and applies it via `apply_block_transition` below and at/above `H`.
3. **No replay e2e.** A pre-gate block with an over-long target must be replayed
   by an armed binary with the same root. This follows from height indexing but
   is unproven end-to-end.
4. **No UTF-8 byte-boundary test.** 128 ASCII bytes vs 129, and a multi-byte
   string whose character count is ≤128 but byte count is >128.
5. **The manifest note is wrong about the path.** It says the cap is enforced
   "on release"; the code enforces it on `Withdraw` settlement (`plan_at_height`)
   and in `validate_at_height`. `Release`/`Refund` do not consult it.
6. **No policy for pre-gate long pending withdrawals.** The gate does not sweep
   them; the release/refund path still accepts them. Decide and document whether
   that is intended.
7. **Governance/fork coordination.** Arming changes consensus verdicts for
   `Withdraw` payloads.

### 2.6 Checklist to arm

- [ ] Add a post-activation block-path e2e: a `SysCallBridge(Withdraw)` payload
      with a 1 MiB (or 129-byte) target applied at `H-1` parks and at `H` is
      refused with no state/rate/balance change; apply the same block via
      `apply_block_transition` and compare the state root across two engines.
- [ ] Add the replay test: the `H-1` block replayed under the armed constant
      keeps its acceptance and root.
- [ ] Add the UTF-8 boundary test (128/129 bytes, multi-byte string).
- [ ] Decide and test the pre-gate long-pending-withdrawal policy
      (release/refund after `H`).
- [ ] Set `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT = H` in `chain_spec.rs`.
- [ ] Add the constant to `current_activation_schedule()`.
- [ ] Update the `feature_gates.rs` row: correct the "release" note, point
      `test:` at the new e2e.
- [ ] Regenerate `docs/feature_gates.yaml` with `stellereum gates --yaml`.
- [ ] Replace the inert pin in `stellereum/tests/activation_gates_inert.rs`
      (and this file's pre-activation assertions) with the post-activation
      expectations.
- [ ] Deploy the armed binary to all nodes before `H`; verify the schedule on
      every node.
- [ ] Never lower `H` afterwards.

---

## 3. `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT`

Pinned by
`stellereum/tests/activation_gate_xshard_bounce_escrow_tests.rs`.
The full defect/invariant analysis is
`stellereum/docs/specs/XSHARD_BOUNCE_ESCROW.md`; this section records the
activation debt.

### 3.1 Where the gate is consulted

| Place | Role |
| --- | --- |
| `chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` | compiled gate, `u64::MAX` |
| `chain_spec::xshard_bounce_escrow_required_active_at(h)` | single activation predicate |
| `runtime/apply.rs` `record_apply_outcome` | produced predicate, control refund, history prune |
| `runtime/anchors.rs` `control_linkage_ok` | 2PC precedence for ack/bounce |
| `runtime/consensus_step.rs` `validate_proposal_unaligned_with_hash` | outbound legacy escrow proof; same-block 2PC precedence |
| `runtime/mev_sync.rs` `propose` | mailbox/derived bounce filtering; legacy outbound selection |
| `state_engine/xshard.rs` `apply_cross_shard_consumptions` | produced skip, control checks, history prune |
| `state_engine/xshard.rs` `record_legacy_escrow_receipts_with_index` | gate-active produced entry + escrow leaf |
| `state_engine/xshard.rs` `has_legacy_escrow_leaf` / `legacy_escrow_leaf_committed` | local proof-free leaf predicates |
| `InMemoryStateEngine::credit_native_transfer` | the refund primitive used by the bounce |

### 3.2 Before the gate (today)

- `produced_cross_shard` is recorded for every outbound legacy `Transfer` in a
  block, regardless of the transaction's apply `status` and regardless of any
  escrow leaf.
- `control_linkage_ok` accepts a bounce when the tx hash is produced, the
  height timeout elapsed, and the lifecycle is not complete. It never asks
  whether the source escrowed anything.
- `validate_proposal` accepts an outbound legacy record if its transaction is
  **present in the block**, not if it applied or committed a debit.
- A timeout bounce refunds `tx.amount` via `credit_native_transfer`.
- Consequences (the defects the gate closes): a failed-apply transaction can be
  bounced and mint `amount`; a §9 2PC PREPARE for the same hash plus a legacy
  record plus a bounce can refund the source while the target's COMMIT credits
  the recipient (double spend).
- The replay mirror `runtime/cluster.rs::ChainState::apply_block` also records
  every outbound unconditionally and pays a bounce on produced + timeout alone.
- Below the gate the live `{0}` chain is byte-identical to the previous build.

### 3.3 After the gate (`height >= H`)

- `produced_cross_shard` is written only for a transaction whose apply
  `status[i]` is true **and** whose committed XSHARD-01 escrow leaf exists, in
  both the runtime and engine mirrors.
- An outbound legacy record must carry the same anchored source-escrow proof an
  inbound legacy credit verifies. A one-step legacy producer anchors to the
  parent root and cannot prove a same-block escrow, so new legacy cross-shard
  **value** is disabled; §9 2PC is the delivery path.
- A bounce requires the committed escrow leaf (or the gate-filtered
  applied-produced set). The proposer filters derived and mailbox bounces the
  same way; apply and validation refuse a forged one.
- Any tx hash owning a §9 2PC record (PREPARE/COMMIT/ABORT, committed or in the
  same block) is refused by the control path.
- All checks run before the consumed/completed inserts, so a refused bounce
  stays replayable and the replay sets never claim a completion that paid
  nothing.
- The first gated block (and every gated block after it) deterministically
  prunes produced entries without a committed escrow leaf. The victim set is a
  pure function of the committed trie, so every node derives the same digest.

### 3.4 Invariants

Before (must remain true while inert):

1. The unconditional produced record and the 64-height bounce/refund are
   byte-identical, including the failed-apply mint shape.
2. A pre-activation block replayed by the same build yields the same root.
3. No wire/transaction/block format or message-id domain changes.

After (must hold at/above `H`):

1. Produced implies a real source debit (`status == true` and committed leaf).
2. No bounce pays without the escrow leaf; no ack/bounce completes a
   2PC-owned hash.
3. Refusal happens before the replay claim, so no paid-nothing completion.
4. The produced set in runtime, engine, persisted snapshot and
   `cross_shard_replay_covers` agree; the history cleanse is deterministic.
5. New cross-shard value moves only through §9 2PC; XPC must be active from
   genesis on the activated shard set.
6. Snapshots taken at/after the first post-gate block restore exactly the
   committed leaves; a below-gate snapshot with an unproven record must fail
   closed rather than re-synthesize it.

### 3.5 What still blocks activation

1. **`runtime/cluster.rs` replay mirror is not gated.** `ChainState::apply_block`
   still records every outbound transfer unconditionally and refunds a bounce
   on produced + timeout with no escrow-leaf and no 2PC check. This violates
   prerequisite 4 of `XSHARD_BOUNCE_ESCROW.md` and can diverge from the live
   path after a reorg/replay, so it must be fixed, not just documented.
2. **No chain-spec-armed multi-shard e2e.** `tests/x8_bounce_escrow_gate.rs`
   exercises the gate through the test-only thread-local override on a
   two-shard cluster; no test arms the compiled constant through the `{0,1}`
   genesis/chain spec and then produces, times out, and settles.
3. **No restart/snapshot e2e at/after `H`.** The history cleanse and the
   `cross_shard_replay_covers`/`verify_restored_root` behaviour across an actual
   process restart are not proven end-to-end.
4. **No reorg e2e through the cluster mirror.** The exact path in blocker 1 is
   also the reorg mirror; it needs a test that a re-applied block derives the
   same produced/completed sets and root as the live apply.
5. **Fresh-genesis decision.** `{0,1}` must be configured with §9 2PC active
   from genesis and `XpcActivation::from_chain_spec()` on every node, because
   the gate disables new legacy value delivery.
6. **Sequencing decision.** Choose `H` strictly above the last height at which
   a legacy transfer may be produced, and drain below-gate legacy transfers
   (ack or timeout bounce) before `H`; a replay restore at/after `H`
   deliberately does not re-synthesize pre-gate leaves.
7. **The live `{0}` chain must stay `u64::MAX`.** Arming on a single-shard
   chain is not the supported path.

### 3.6 Checklist to arm

- [ ] Fix `runtime/cluster.rs::ChainState::apply_block`: same produced predicate
      (`status && escrow leaf`), same escrow-leaf check and 2PC precedence for
      control records, same deterministic history prune as `runtime/apply.rs`.
- [ ] Add a `{0,1}` post-activation e2e with the gate armed at `H` through the
      chain spec / genesis identity (not only the thread-local override):
      a genuine §9 2PC transfer credits once; a failed-apply outbound never
      bounces; a 2PC-owned hash never bounces; an escrow-proven pre-`H` legacy
      transfer still refunds once; the first post-`H` block prunes an unproven
      produced entry.
- [ ] Add the restart/snapshot e2e at/after `H`: take a snapshot after the first
      gated block, restore, and verify `cross_shard_replay_covers` /
      `verify_restored_root` against the committed root.
- [ ] Add the reorg e2e through `ChainState::apply_block` on the same fixture.
- [ ] Choose `H >` the last legacy-production height and drain legacy transfers.
- [ ] Set `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT = H` in the `{0,1}` coordinated
      chain spec; keep the live `{0}` value at `u64::MAX`.
- [ ] Update the `feature_gates.rs` row: point `test:` at the new e2e.
- [ ] Regenerate `docs/feature_gates.yaml` with `stellereum gates --yaml`.
- [ ] Replace the inert pin in `stellereum/tests/activation_gates_inert.rs`
      (and this file's pre-activation assertions) with the post-activation
      expectations; update `tests/x8_bounce_escrow_gate.rs` assumptions if its
      below-gate fixture no longer models the shipped spec.
- [ ] Deploy the armed `{0,1}` build/genesis to all nodes before `H`; verify
      every node has the same shard set, XPC activation and `H`.
- [ ] Never lower `H` afterwards.

---

## 4. `WASM_TABLE_ELEMENTS_CAP_HEIGHT`

Pinned by `stellereum/tests/w4_engine_hardening_tests.rs`.

### 4.1 Where the gate is consulted

| Place | Role |
| --- | --- |
| `chain_spec::WASM_TABLE_ELEMENTS_CAP_HEIGHT` | compiled gate, `u64::MAX` |
| `chain_spec::wasm_table_elements_cap_height()` | effective height (test/debug override) |
| `chain_spec::wasm_table_elements_cap_active_at(h)` | single activation predicate |
| `contract::MAX_CONTRACT_TABLE_ELEMENTS` | table element cap: `16_384` |
| `contract::validate_memory_limits` / `store_limits_with_table_cap` | section-4 `Table` declaration check and `wasmi::StoreLimits::table_elements` budget |
| `contract::ContractRegistry::validate_code_at` / `validate_code_hardened_at` | height-gated code validation |
| `contract::run_contract_hardened_at` | height-gated execution budget |
| `svm::Svm` (`SysCallDeployContract` / contract call paths) | consensus deploy/execute call sites (must thread block `height` before arming) |
| RPC pre-validation paths | enforces `enforce_table_cap = true` immediately (node-local mempool filter) |

### 4.2 Checklist to arm

- [ ] Thread block `height` through all consensus deploy/execute call sites
      (`validate_code_hardened_at` / `run_contract_hardened_at`) while keeping
      node-local RPC pre-validation enforcing the cap immediately.
- [ ] Register `WASM_TABLE_ELEMENTS_CAP_HEIGHT` in
      `chain_spec::current_activation_schedule()`.
- [ ] Add a post-activation block-path e2e (`apply_block_transition` on two
      engines): `(table 1000000 funcref)` deploys below `H` and fails with
      `ContractError::InvalidWasm` at/above `H`, with identical `state_root`
      across both engines.
- [ ] Add a historical replay e2e: a pre-`H` block deploying an oversized table
      replays under the armed binary with the identical state root.
- [ ] Set `WASM_TABLE_ELEMENTS_CAP_HEIGHT = H` in `chain_spec.rs`.
- [ ] Update the `wasm-table-elements-cap` row in `feature_gates.rs`: point
      `test:` at the new e2e and update the note.
- [ ] Regenerate `docs/feature_gates.yaml` with `stellereum gates --yaml`.
- [ ] Update `stellereum/tests/w4_engine_hardening_tests.rs` (and any inert
      pin assertions) to reflect the armed height `H`.
- [ ] Deploy the armed binary to all nodes before `H`; verify
      `stellereum gates` and `current_activation_schedule()` match across every
      node.
- [ ] Never lower `H` afterwards.

---

## 5. `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT`

### 5.1 Where the gate is consulted

| Place | Role |
| --- | --- |
| `chain_spec::FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT` | compiled gate, `u64::MAX` |
| `chain_spec::falcon_host_fuel_v2_active_at(h)` | single activation predicate |
| `contract::FUEL_FALCON512_VERIFY` (`2_000`) / `FUEL_FALCON512_VERIFY_V2` (`150_000`) | pre- vs post-activation base fuel for `host.falcon512_verify` |
| `svm::Svm` (`SysCallDeployContract`) | single module validation and single `(start)` fuel deduction from `state.gas_remaining` at/above `H` |

### 5.2 Checklist to arm

- [ ] Confirm `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT` (`u64::MAX` compiled
      default), `FUEL_FALCON512_VERIFY_V2 = 150_000`, and single `(start)` gas
      charging in `SysCallDeployContract` are wired and registered in
      `chain_spec::current_activation_schedule()` and `feature_gates::table()`.
- [ ] Record `benches/pq_end_to_end.rs` 1-vCPU vs 16-core verification timings
      justifying `FUEL_FALCON512_VERIFY_V2 = 150_000`.
- [ ] Add/verify a differential pre/post-activation test: pre-`H` gas/fuel is
      byte-identical to legacy (`2_000` base fuel + legacy `(start)` billing);
      post-`H` charges `150_000` base fuel (+ byte charges) and deducts single
      `(start)` fuel from `state.gas_remaining`.
- [ ] Add/verify a contract-level test proving a `(start)` loop cannot execute
      twice or bypass `state.gas_remaining`.
- [ ] Add/verify a post-activation `apply_block_transition` e2e and historical
      replay pin across two engines.
- [ ] Set `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT = H` in `chain_spec.rs`,
      update the `feature_gates.rs` row (`test:` pointing to the proving e2e),
      and regenerate `docs/feature_gates.yaml` with `stellereum gates --yaml`.
- [ ] Update inert pin assertions in the `activation_gate_*` tests to match
      the armed height `H`.
- [ ] Deploy the armed binary to all nodes before `H`; verify
      `stellereum gates` and `current_activation_schedule()` match across every
      node.
- [ ] Never lower `H` afterwards.
