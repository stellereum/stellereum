# Activation Batch 1 — Unified Specification

Status: **CANDIDATE FOR COORDINATED ROLLOUT** (2026-11-25). Every item in
Batch 1 is height-gated and **must remain `INERT` (`u64::MAX`)** until its
pre-activation pins, post-activation E2E proofs, `current_activation_schedule()`
entries, and `docs/feature_gates.yaml` manifest are green and all four
validators stage and activate the same binary strictly before the chosen
activation height `H`.

## 1. Overview of Batch 1 Candidates (A1–A7)

Every change in this batch alters consensus-visible block validity, execution
gas/fuel, contract-visible state, settlement verdicts, or deterministic validator
jailing. Changing any of them without a shared activation height `H` would cause
nodes to disagree on historical blocks or diverge on live `state_root` /
validator-set commitments.

| # | Gate / Decision | Constant / Symbol | Compiled Default | Chain Scope | Summary |
|---|---|---|---|---|---|
| A1 | WASM table element cap | `WASM_TABLE_ELEMENTS_CAP_HEIGHT` | `u64::MAX` | `{0}` and `{0,1}` | Cap WASM section-4 `Table` declarations and `wasmi` `StoreLimits::table_elements` at `MAX_CONTRACT_TABLE_ELEMENTS` (`16_384`) |
| A2 | Falcon host fuel v2 + single `(start)` gas charging | `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT` | `u64::MAX` | `{0}` and `{0,1}` | Raise `host.falcon512_verify` base fuel from `FUEL_FALCON512_VERIFY` (`2_000`) to `FUEL_FALCON512_VERIFY_V2` (`150_000`), validate deploy modules once, and charge `(start)` fuel to `state.gas_remaining` |
| A3 | Contract `host.block_hash` | `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` | `u64::MAX` | `{0}` and `{0,1}` | Expose `block.prev_hash` (parent block hash) via `host.block_hash` on block execution paths instead of `[0u8; 32]` |
| A4 | Bridge withdrawal target-address cap | `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` | `u64::MAX` | `{0}` and `{0,1}` | Cap `BridgeIntent::Withdraw.target_address` at `MAX_BRIDGE_TARGET_ADDRESS_BYTES` (`128` UTF-8 bytes) during `validate_at_height` and `plan_at_height` settlement |
| A5 | Cross-shard bounce escrow | `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` | `u64::MAX` | `{0,1}` only (`{0}` stays `u64::MAX`) | Require committed XSHARD-01 escrow leaf (`status[i] && L(T)`) for produced/outbound/bounce paths, §9 2PC precedence, `runtime/cluster.rs` parity, and deterministic history cleanse |
| A6 | Downtime miss budget decision | `DOWNTIME_MISS_THRESHOLD` (`42`) / `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` | `42` (frozen) | `{0}` and `{0,1}` | Decision record: keep `42` if C/A/D move to 2 vCPU, or gate efficiency-based jailing / `150`-miss interim behind `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` if 1 vCPU remains |
| A7 | Actor mailbox hardening | `ACTOR_MAILBOX_HARDENING_HEIGHT` | `u64::MAX` | `{0}` and `{0,1}` | Height-gate hardened actor mailbox invariants: deterministic sorted-recipient FIFO delivery, `MAX_ACTOR_ROUNDS`/`MAX_ACTOR_MSGS_PER_BLOCK` caps, `MessageUndo` atomic rollback + bounce-once refund, and block-level `check_actor_cap` parity |

All height-gated constants follow strict `>= H` activation semantics with the
`u64::MAX` sentinel meaning "never active" (even at `height == u64::MAX`).
Lowering a compiled constant without updating its inert pin test and
regenerating `docs/feature_gates.yaml` via `stellereum gates --yaml` is rejected
by CI.

---

## 2. Detailed Specifications

### A1 — `WASM_TABLE_ELEMENTS_CAP_HEIGHT`

- **Code surface**: `stellereum/src/chain_spec.rs` (`WASM_TABLE_ELEMENTS_CAP_HEIGHT`,
  `wasm_table_elements_cap_height()`, `wasm_table_elements_cap_active_at(h)`),
  `stellereum/src/contract.rs` (`MAX_CONTRACT_TABLE_ELEMENTS = 16_384`,
  `validate_memory_limits`, `store_limits_with_table_cap`, `validate_code_at`,
  `validate_code_hardened_at`, `run_contract_hardened_at`),
  `stellereum/src/svm.rs` (consensus deploy/call call sites).
- **Threat**: `store_limits()` previously bounded linear memory pages
  (`MAX_CONTRACT_PAGES`) and `validate_memory_limits` inspected WASM section 5
  (memory), leaving section 4 (table) unbounded. A ~200-byte module declaring
  `(table 100000000 funcref)` caused `wasmi` to allocate gigabytes at
  instantiation time, enabling single-transaction remote OOM across every
  validator.
- **Pre-activation (`height < H`, or `u64::MAX`)**:
  - Consensus deploy and execution paths keep legacy Ruleset v7 uncapped table
    acceptance for byte-identical historical replay.
  - Node-local RPC pre-validation (`validate_code_with_table_cap(..., true)` /
    `validate_code_hardened_with_table_cap(..., ..., true)`) enforces the cap
    immediately so oversized modules are rejected before mempool admission
    without altering consensus replay.
- **Post-activation (`height >= H`)**:
  - Consensus deploy (`validate_code_at` / `validate_code_hardened_at`) and
    execution (`run_contract_hardened_at`) reject any module whose section-4
    `Table` declaration or exported `ExternType::Table` has `minimum` or
    `maximum` above `MAX_CONTRACT_TABLE_ELEMENTS` (`16_384`) with
    `ContractError::InvalidWasm`.
  - The `wasmi` `StoreLimits` budget enforces
    `.table_elements(MAX_CONTRACT_TABLE_ELEMENTS)`.
- **Prerequisites before arming**:
  1. Block `height` threaded through all consensus deploy/execute call sites in
     `svm.rs` (`validate_code_hardened_at` and `run_contract_hardened_at`).
  2. `WASM_TABLE_ELEMENTS_CAP_HEIGHT` registered in
     `chain_spec::current_activation_schedule()`.
  3. Post-activation E2E (`activation_gate_*` / `w3_*`) proving `(table 1000000 funcref)`
     deploys at `H - 1`, fails with `InvalidWasm` at `H`, and replays `H - 1`
     with identical `state_root` across independent engines.
  4. `feature_gates.rs` updated with proving test path and
     `docs/feature_gates.yaml` regenerated (`stellereum gates --yaml`).

### A2 — `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT`

- **Code surface**: `stellereum/src/chain_spec.rs`
  (`FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT`), `stellereum/src/contract.rs`
  (`FUEL_FALCON512_VERIFY = 2_000`, `FUEL_FALCON512_VERIFY_V2 = 150_000`,
  single `(start)` fuel accounting), `stellereum/src/svm.rs`
  (`SysCallDeployContract`), `stellereum/src/feature_gates.rs`.
- **Threat**:
  1. `FUEL_FALCON512_VERIFY = 2_000` against a 50M block budget allows one
     transaction to invoke ~24 750 Falcon-512 verifications (~several ms each),
     stalling block execution for seconds per transaction.
  2. `SysCallDeployContract` validated the module through
     `validate_code_hardened` (charging `(start)` against an isolated
     `VALIDATE_CODE_START_FUEL_LIMIT` budget rather than `state.gas_remaining`),
     creating a double-validation / free-`(start)` gas accounting gap.
- **Pre-activation (`height < H`, or `u64::MAX`)**:
  - `host.falcon512_verify` charges `FUEL_FALCON512_VERIFY` (`2_000`) plus
    input byte lengths (`mlen + pklen + siglen`).
  - `SysCallDeployContract` retains legacy Ruleset v7 gas/fuel accounting for
    byte-identical historical replay.
- **Post-activation (`height >= H`)**:
  - `host.falcon512_verify` charges `FUEL_FALCON512_VERIFY_V2` (`150_000`) base
    fuel plus input byte lengths (`mlen + pklen + siglen`).
  - `SysCallDeployContract` validates the WASM module **once** and charges the
    actual `(start)` fuel consumed against the caller's `state.gas_remaining`
    (out-of-gas/fuel reverts deterministically).
- **Prerequisites before arming**:
  1. `benches/pq_end_to_end.rs` calibration data recorded on 1-vCPU and
     16-core hosts confirming `150_000` fuel accurately bounds worst-case
     verification wall time.
  2. Differential pre/post-activation test proving pre-`H` fuel/gas is
     byte-identical to legacy execution while post-`H` charges `150_000` base
     fuel and deducts single `(start)` execution fuel from `state.gas_remaining`.
  3. Contract-level test proving a `(start)` loop cannot run twice or bypass
     `state.gas_remaining`.
  4. Gate registered in `current_activation_schedule()` and `feature_gates.rs`;
     `docs/feature_gates.yaml` regenerated.

### A3 — `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT`

- **Code surface**: `stellereum/src/chain_spec.rs`
  (`CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT`, `contract_block_hash_active_at(h)`),
  `stellereum/src/svm.rs` (`VmExecOptions::contract_block_hash`,
  `Svm::execute_inner`), `stellereum/src/contract.rs`
  (`ContractCallContext::block_hash`, `host.block_hash`),
  `stellereum/src/state_engine/apply.rs` (`apply_block_transition`,
  `execute_payload_with_preverify_at_height_and_parent`).
- **Pre-activation (`height < H`, or `u64::MAX`)**:
  - `host.block_hash` succeeds, charges `FUEL_BLOCK_HASH` (`10`), and writes
    `[0u8; 32]` because `Svm::execute_inner` substitutes zero while the gate is
    inactive. Pinned by `stellereum/tests/activation_gate_contract_block_hash_tests.rs`.
- **Post-activation (`height >= H`)**:
  - `Svm::execute_inner` forwards `opts.contract_block_hash` into
    `ContractCallContext::block_hash`.
  - Live block execution passes the **parent** block hash (`block.prev_hash`),
    never `block.compute_hash()` (which commits `body_commitment` including
    execution outputs like `cross_shard_out`).
  - Callers without a block context (single-tx `apply_transaction` and RPC
    preview) continue passing `[0u8; 32]`; this is a deliberate non-block
    boundary and must be documented/tested so RPC preview is not mistaken for
    block-context execution.
- **Prerequisites before arming** (from `docs/ACTIVATION_GATES.md` §1):
  1. Cross-node `apply_block_transition` E2E across two independent engines
     verifying `host.block_hash == block.prev_hash != block.compute_hash()` and
     identical resulting `state_root`.
  2. Reorg re-apply and snapshot/restart replay E2E parity.
  3. Non-block context test + written policy decision for single-tx / RPC preview.
  4. Audit of all `ContractRegistry::call_with_context` callers confirming
     consensus execution routes solely through SVM.
  5. Inert pin update + `feature_gates.rs` / `docs/feature_gates.yaml` sync.

### A4 — `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT`

- **Code surface**: `stellereum/src/chain_spec.rs`
  (`BRIDGE_TARGET_ADDRESS_CAP_HEIGHT`, `bridge_target_address_cap_active_at(h)`),
  `stellereum/src/bridge.rs` (`MAX_BRIDGE_TARGET_ADDRESS_BYTES = 128`,
  `validate_bridge_target_address_len`, `BridgeIntent::validate_at_height`,
  `BridgeState::plan_at_height`), `stellereum/src/state_engine/`
  (`settle_bridge_native`).
- **Threat**: Before the gate, `Withdraw.target_address` only checks non-empty
  after `trim()`. Because the hourly rate limit tracks withdrawn `amount` only,
  arbitrary-length addresses (e.g. 1 MiB) can be parked into `pending_withdrawals`
  in consensus state for zero bridge value.
- **Pre-activation (`height < H`, or `u64::MAX`)**:
  - `validate_bridge_target_address_len` is a no-op; oversized targets park
    normally and remain releasable/refundable. Pinned by
    `stellereum/tests/activation_gate_bridge_target_address_cap_tests.rs`.
- **Post-activation (`height >= H`)**:
  - `BridgeIntent::Withdraw` with `target_address.len() > 128` UTF-8 bytes
    (`str::len()`) is rejected at `validate_at_height` and `plan_at_height`
    settlement **before** any rate-window, queue, or balance write.
  - `Release` and `Refund` remain length-agnostic so pre-gate oversized parked
    withdrawals remain finalizable/refundable unless an explicit migration is
    specified.
- **Prerequisites before arming** (from `docs/ACTIVATION_GATES.md` §2):
  1. Register `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` in
     `chain_spec::current_activation_schedule()`.
  2. Block-path `apply_block_transition` E2E (`H - 1` parks, `H` refuses with
     unchanged state/rate/balance, matching `state_root` across two engines).
  3. Replay E2E confirming `H - 1` oversized withdrawal replays identically under
     the armed binary, plus UTF-8 multi-byte 128/129-byte boundary test.
  4. Documented and tested policy confirming pre-gate long `pending_withdrawals`
     remain releasable/refundable post-`H`.
  5. Correct `feature_gates.rs` note (enforced on `Withdraw` settlement/parking,
     not on `Release`) and regenerate `docs/feature_gates.yaml`.

### A5 — `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` (Multi-Shard `{0,1}` Only)

- **Code surface**: `stellereum/src/chain_spec.rs`
  (`XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT`,
  `xshard_bounce_escrow_required_active_at(h)`),
  `stellereum/src/runtime/{apply,anchors,consensus_step,mev_sync,cluster}.rs`,
  `stellereum/src/state_engine/xshard.rs`. Full analysis:
  `stellereum/docs/specs/XSHARD_BOUNCE_ESCROW.md`.
- **Chain scope**: **Live single-shard `{0}` keeps `u64::MAX` (`INERT`)**. This
  gate is armed only on a coordinated `{0,1}` multi-shard chain with
  `XPC_ACTIVATION_HEIGHT = 0` (`XpcActivation::from_chain_spec()`).
- **Pre-activation (`height < H`, or `u64::MAX`)**:
  - Legacy unconditional `produced_cross_shard` recording and 64-height timeout
    bounce remain byte-identical. Pinned by
    `stellereum/tests/activation_gate_xshard_bounce_escrow_tests.rs`.
- **Post-activation (`height >= H`)**:
  - `produced_cross_shard` records a transaction only if `status[i] == true`
    **and** its committed XSHARD-01 escrow leaf `L(T)` exists.
  - Outbound legacy records require `verify_cross_shard_escrow_anchored`.
  - Bounces require `has_legacy_escrow_leaf` and are refused for any tx hash
    owning a §9 2PC record (`PREPARE`/`COMMIT`/`ABORT`).
  - Every gated block deterministically prunes produced entries lacking
    `legacy_escrow_leaf_committed` before inserting new entries.
- **Closure of `runtime/cluster.rs` parity blocker**:
  - `docs/ACTIVATION_GATES.md` §3.5 blocker 1 and `XSHARD_BOUNCE_ESCROW.md` §5.4
    identified that `runtime/cluster.rs::ChainState::apply_block` still recorded
    every outbound transfer unconditionally, refunded timeout bounces without an
    escrow-leaf or §9 2PC check, and lacked the deterministic produced-set prune.
  - Arming A5 on `{0,1}` requires `ChainState::apply_block` in
    `runtime/cluster.rs` to share full predicate parity with
    `runtime/apply.rs::record_apply_outcome` and `state_engine/xshard.rs`
    (`status[i] && L(T)` produced rule, escrow-leaf + 2PC-precedence control
    checks, and deterministic history prune), verified by a `{0,1}`
    chain-spec-armed E2E, a `ChainState::apply_block` reorg E2E, and a
    post-`H` snapshot/restart E2E.
  - Operational sequencing on `{0,1}`: choose `H` strictly above the last
    legacy-transfer production height and drain open legacy transfers before `H`.

### A6 — `DOWNTIME_MISS_THRESHOLD` Decision Record

- **Code surface**: `stellereum/src/staking.rs` (`DOWNTIME_MISS_THRESHOLD = 42`,
  `REENTRY_LIVENESS_WINDOW_HEIGHTS = 42`, `JAIL_RELEASE_DELAY_HEIGHTS = 4_000`,
  `DOWNTIME_PENALTY_COOLDOWN = 500`).
- **Problem statement**:
  - `DOWNTIME_MISS_THRESHOLD = 42` is frozen under `AGENTS.md §7`. Ruleset v2
    calibrated `42` for a `240 ms` block tempo (`42 × 240 ms = 10.08 s`).
  - The live cluster runs at `STELL_MIN_BLOCK_MS = 400 ms`
    (`scripts/cluster-nodes.conf`), making `42` consecutive misses equal to
    **`16.8 s`**.
  - On 1-vCPU validator hosts (`nodeC` at ~68% steady CPU from the node alone,
    plus `nodeA`/`nodeD`), brief CPU/IO contention or binary-swap restarts can
    exceed `16.8 s`, jailing the validator for `JAIL_RELEASE_DELAY_HEIGHTS = 4_000`
    blocks (~26.7 min at 400 ms/block) until a cold-key `unjail` runs (currently
    mitigated operationally by `scripts/auto-unjail.sh`).
- **Decision options (select one before Batch 1 freeze)**:
  1. **Option 1 — Keep `DOWNTIME_MISS_THRESHOLD = 42` + upgrade C/A/D to 2 vCPU**:
     - **Protocol/code change**: None (`0` risk to frozen staking math or
       `REENTRY_LIVENESS_WINDOW_HEIGHTS`).
     - **Condition**: `nodeC`, `nodeA`, and `nodeD` are moved to ≥2 vCPU hosts
       and heavy builds remain isolated off validator hosts (`taskset` / separate
       build box). Preserves fast `16.8 s` dead-validator eviction.
  2. **Option 2 — `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` with efficiency-based jailing**:
     - **Rule**: Jail when a validator misses more than `X%` of its assigned
       slots over a deterministic rolling window (tempo-independent, analogous
       to TON `low_efficiency` / Solana skip-rate).
     - **Requirements**: Deterministic window definition, deterministic
       block-carried attribution evidence, explicit transition rule for
       validators jailed under the legacy rule at height `H`, spec update +
       audit note (`AGENTS.md §7`), and E2E tests.
  3. **Option 3 — `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` with `150`-miss interim (`60 s` at `400 ms`)**:
     - **Rule**: If 1-vCPU hosts remain temporarily and Option 2 is deferred,
       gate `42 -> 150` consecutive misses behind
       `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` with an explicit expiry/sunset.
     - **Trade-off**: Minimal code complexity, but increases the time a genuinely
       offline validator stays in the active set from `16.8 s` to `60 s` and
       requires a spec update + audit note (`AGENTS.md §7`).
- **Consensus invariant**: Any change away from `42` (Option 2 or Option 3)
  **must** be height-gated via `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` registered in
  `current_activation_schedule()` and `feature_gates.rs`. Mixed thresholds across
  validators cause deterministic validator-set divergence.

### A7 — `ACTOR_MAILBOX_HARDENING_HEIGHT`

- **Code surface**: `stellereum/src/chain_spec.rs`
  (`ACTOR_MAILBOX_HARDENING_HEIGHT`, `actor_mailbox_hardening_active_at(h)` —
  to be wired), `stellereum/src/state_engine/apply/actor.rs`
  (`apply_actor_messages_at`, `deliver_actor_message`, `try_deliver`),
  `stellereum/src/state_engine/apply/block.rs` (`apply_block_transition` step 1b),
  `stellereum/src/state_engine/mod.rs` (`MAX_ACTOR_ROUNDS = 8`,
  `MAX_ACTOR_MSGS_PER_BLOCK = 4_096`), `stellereum/src/runtime/{apply,mev_sync,consensus_step}.rs`
  (`check_actor_cap`), `stellereum/src/node/sync.rs` (walk-side `check_actor_cap`),
  `stellereum/src/feature_gates.rs`.
- **Threat**:
  1. Unordered `HashMap` recipient iteration during the mailbox pass causes
     two validators applying the same block to deliver interdependent actor
     messages in different orders and diverge on `state_root`.
  2. Half-applied recipient/third-party mutations on body revert, out-of-gas, or
     unfunded nested sends leak partial balance state unless rolled back
     atomically before issuing a single bounce refund.
  3. Unbounded mailbox recursion or blocks exceeding `MAX_ACTOR_MSGS_PER_BLOCK`
     leave root-invisible queued messages across block boundaries unless
     enforced identically at propose, vote/validate, and sync-walk boundaries.
- **Pre-activation (`height < H`, or `u64::MAX`)**:
  - Historical blocks keep legacy Ruleset v7 replay semantics byte-for-byte
    with empty queues at block boundaries and no change to genesis/historical
    KATs or `AccountState` leaf encoding.
- **Post-activation (`height >= H`)**:
  - `apply_actor_messages_at` executes deterministically in sorted recipient
    address order (`sort_unstable`) with FIFO per-recipient ordering, bounded
    by `MAX_ACTOR_ROUNDS` (`8`) and `MAX_ACTOR_MSGS_PER_BLOCK` (`4_096`).
  - Failed deliveries roll back all touched accounts via `MessageUndo` and
    bounce once as a pure refund (`bounced: true`, body never re-executed).
  - Propose, consensus validation, and sync walk enforce identical
    `check_actor_cap` limits (`backlog + block_sends <= MAX_ACTOR_MSGS_PER_BLOCK`)
    so no node can admit or adopt a block that leaves root-invisible mailbox
    state across a block boundary.
  - Any future persistent cross-block inbox state (`ACTORQ1` conditional leaf)
    remains out of scope and would require its own separate activation gate.
- **Prerequisites before arming**:
  1. Wire `ACTOR_MAILBOX_HARDENING_HEIGHT` (compiled default `u64::MAX`) in
     `chain_spec.rs`, `current_activation_schedule()`, and `feature_gates.rs`.
  2. Cross-node `apply_block_transition` E2E proving identical `state_root`
     under multi-recipient / multi-round / revert-and-bounce workloads and
     uniform rejection of over-cap blocks across propose, consensus, and walk.
  3. Inert pin test + `docs/feature_gates.yaml` regeneration via
     `stellereum gates --yaml`.

---

## 3. Rollout Order and Invariants

For the exact operator procedure, pre-flight commands, canary checks, and
post-`H` verification, follow `ops/activation_rollout_runbook.md`.

1. Land all Wave 3 gate wiring (`chain_spec.rs`, `current_activation_schedule()`,
   `feature_gates.rs`, `runtime/cluster.rs` parity) with every new gate at
   `u64::MAX` and `activation_gate_*` / `w3_*` tests green.
2. Freeze the chosen activation height `H` (and A6 decision) in `chain_spec.rs`,
   update `feature_gates.rs` proving test names, update inert pin tests, and
   regenerate `docs/feature_gates.yaml` via `stellereum gates --yaml` (on `{0}`,
   keep `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT = u64::MAX`).
3. Stage (`rolling-deploy.sh stage`) and canary-activate
   (`rolling-deploy.sh activate --canary`) before `H`, then roll out one node
   at a time (`C -> A -> D -> B` or `B -> D -> A -> C`) with **4/4** verified
   before every restart and `scripts/auto-unjail.sh` kept active.
4. Verify every node reports identical `stellereum gates` heights and matching
   `current_activation_schedule()` logs **before** crossing `H`.
5. Cross `H` and execute post-`H` state-root and metric verification. Rollback
   after `H` is impossible without a coordinated snapshot restore to height `< H`.

### Batch-Wide Invariants

- **Unchanged core**: No change to block hash inputs, QC wire bytes, signature
  domains, quorum math, or `apply()` semantics for non-gated transactions (and
  no change to staking math unless A6 Option 2/3 explicitly activates
  `JAIL_BUDGET_V2_ACTIVATION_HEIGHT`).
- **Fail-closed upgrade discipline**: A node that fails verification or misses
  the upgrade window before `H` must not participate with a mismatched binary;
  roll back to `stellereum.prev` before `H` or halt and snapshot-sync after `H`.
- **No silent arming**: Every `u64::MAX` gate remains pinned by tests that fail if
  a constant is lowered without updating the proving E2E and manifest.
