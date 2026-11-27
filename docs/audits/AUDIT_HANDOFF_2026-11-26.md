# External Audit Handoff — Stellereum (2026-11-26)

## Document status

| Field | Value |
|---|---|
| Generated | 2026-11-26 |
| Snapshot commit | `ab0adbf086779a5638459e58d7e6a5e9949ffdad` (`git rev-parse HEAD`) |
| Snapshot commit subject | `ops(observability): wire standalone stell-status metrics scrape into Prometheus` (committed 2026-11-25T23:54:31+03:00) |
| Working tree | **DIRTY** — 127 modified/untracked entries at generation time (see §2.5 and §4.6) |
| Re-execution | **None.** No `cargo`, `git` write, fuzz, or perf command was run to produce this document. Every number below is either read from a source file/constant or quoted from the document named beside it. |
| Evidence rule | A claim that is not readable in a listed file is marked `UNVERIFIED`. |

This is a **handoff package**, not an audit result and not a security certification. It tells an
external auditor where the frozen consensus identity is defined, which activation gates exist,
which commands reproduce the project's own gates, and what remains unproven.

**Important snapshot caveat.** The working tree is dirty. Two consensus-adjacent files differ
from HEAD:

* `stellereum/src/feature_gates.rs` — uncommitted change adds four gate rows
  (`sortition-unbiased`, `jail-budget-v2`, `contract-abi-onchain`, `execution-pipeline-v1`) and
  updates three test paths. At HEAD the table has 10 rows; the working tree has 14.
* `stellereum/src/chain_spec.rs` — uncommitted change adds the four matching constants, their
  helpers, and four `current_activation_schedule()` entries. At HEAD the schedule has 23 entries;
  the working tree has 27.

Rows marked **[WORKTREE]** exist only in the uncommitted working tree. An auditor checking out
`ab0adbf` will not see them. Nothing else in the gate values below differs between HEAD and the
working tree; `protocol.rs`, `bridge.rs`, `bridge_adapters.rs`, `pq_registry.rs`,
`state_engine/mod.rs`, `sharding/block.rs` and `tokenomics.rs` are clean at HEAD in this snapshot.

---

## 1. Scope and freeze

### 1.1 Consensus identity

Read from `stellereum/src/protocol.rs` (clean at HEAD). Values are compile-time constants; the
fork id is an FNV-1a-32 fold, not a hash of the binary.

| Field | Value | Defining line |
|---|---|---|
| `PROTOCOL_VERSION` | `1.0` (`PROTOCOL_MAJOR = 1`, `PROTOCOL_MINOR = 0`) | `protocol.rs:51-61` |
| `CONSENSUS_RULESET_VERSION` | `7` | `protocol.rs:112` |
| `DOMAIN_SET_VERSION` | `4` | `protocol.rs:117` |
| `FORK_ID` | `0x3ae00ebc` | computed at `protocol.rs:261-265`; pinned by tests listed in §1.2 |
| `DEFAULT_CHAIN_ID` | `5757` | `stellereum/src/zkml.rs:217` |
| `MAX_BLOCK_TIMESTAMP_DRIFT_MS` | `3_600_000` (1 h; block timestamps are seconds) | `protocol.rs:136` |

`FORK_ID` is defined by:

```text
FORK_ID = derive_fork_id(DEFAULT_CHAIN_ID, CONSENSUS_RULESET_VERSION, FORK_ID_RULES)
```

* `derive_fork_id` — `protocol.rs:220-254`. Folds, in order: the literal
  `b"STELL_FORK_ID_V1"`, `DOMAIN_SET_VERSION`, chain id, ruleset version, 16 domain strings
  (`protocol.rs:227-247`), then all 32 `FORK_ID_RULES` values (`protocol.rs:162-196`).
* `FORK_ID` — `protocol.rs:261-265`.
* The identity is installed at process startup by `install_chain_identity()`
  (`protocol.rs:282-284`); a different `fork_id` is refused for consensus at handshake
  (`protocol.rs:29-36`, `negotiate` re-export at `protocol.rs:40-44`).
* Independent pins of the value `0x3ae00ebc`:
  `stellereum/tests/r1_frozen_apply_svm_tests.rs:164`,
  `stellereum/tests/w4_sub_nano_tests.rs:229`,
  `stellereum/tests/r2_runtime_rpc_e2e_tests.rs:823`,
  `stellereum/tests/r3_vm_engine_apply_tests.rs:236`,
  `stellereum/tests/protocol_negotiation_tests.rs:306-314`.

### 1.2 Frozen wire-format checklist for the auditor

Treat the following as frozen for this snapshot. A change to any of them is a consensus change
requiring a new `FORK_ID` (and, per `docs/RULESET_V7.md`, a new genesis), not a patch.

- [ ] **Protocol identity** — `PROTOCOL_MAJOR=1`, `PROTOCOL_MINOR=0`,
      `CONSENSUS_RULESET_VERSION=7`, `DOMAIN_SET_VERSION=4`, `FORK_ID=0x3ae00ebc`.
- [ ] **The 32 `FORK_ID_RULES` constants** — `protocol.rs:162-196`. They include consensus
      bounds, staking thresholds, CN-VRF/MMR/MEV epochs, the supply cap, and the nine Ruleset v7
      activation heights.
- [ ] **The 16 folded domain strings** — 7 pre-v7 domains (`protocol.rs:227-233`) plus 9 v7
      domains (`protocol.rs:236-247`). A rename or byte change moves `FORK_ID`.
- [ ] **Block hashing** — two-level `BlockHeader` v4 with
      `BODY_COMMITMENT_V4_DOMAIN = b"STELLEREUM_BODY_V4\0"` and
      `HEADER_COMMIT_V4_DOMAIN = b"STELLEREUM_HDR_V4\0"`
      (`stellereum/src/sharding/block.rs:181-187`), active from height 0.
- [ ] **Vote/QC wire** — V3 vote preimage with shard id (`STELLEREUM_BFT_VOTE_V3`), QC/UQC and
      PQ magics, PQ envelopes. All are folded into the fork id; see `protocol.rs:215-233` and
      `docs/RULESET_V3.md`.
- [ ] **Canonical PQ1 envelope decoding** — `PqSignatureEnvelope::decode_canonical` /
      `decode_at_height`, active at height 0 via
      `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` (`docs/RULESET_V7.md` item 2).
- [ ] **Bridge V2 preimages** — `STELL_BRIDGE_RELEASE_RECEIPT_V2`
      (`stellereum/src/bridge.rs:99`), `STELL_BRIDGE_HEADER_V2`
      (`stellereum/src/bridge_adapters.rs:210`), `STELL_BRIDGE_DEPOSIT_FAILURE_V1`
      (`stellereum/src/bridge.rs:1177-1192`), plus the TON/EVM/multisig release literals folded
      at `protocol.rs:245-247`.
- [ ] **PQ validator identity** — `STELL_PQ_KEY_POP_V1` and `STELL_VAL_ID_V1`
      (folded at `protocol.rs:238-239`; lifecycle active at height 0,
      `stellereum/src/pq_registry.rs:92`).
- [ ] **Quorum math** — `floor(2W/3)+1` power, empty set returns `u64::MAX`, µQC accelerator
      capped at 128 seats with a network-anchored floor. Frozen; cited by
      `docs/BFT_COMPARISON.md` and `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md`.
- [ ] **State transition and domain set** — `apply()`, the committed domain set
      (`DOMAIN_SET_VERSION=4`), `state_root`, staking math, and mempool admission. These are
      consensus-adjacent but not all are literally "wire"; treat them as frozen under
      `AGENTS.md` §7.

**Caveat the auditor must carry forward:** the four **[WORKTREE]** gates
(`SORTITION_UNBIASED`, `JAIL_BUDGET_V2`, `CONTRACT_ABI_ONCHAIN`, `EXECUTION_PIPELINE_V1`)
are **not** in `FORK_ID_RULES` (the list ends at `SUB_NANO_STRICT`, `protocol.rs:195`).
Arming one of them would change consensus behaviour without moving `FORK_ID`; coordination is
by the shared activation height and the same binary, not by the fork id. Do not assume
"same FORK_ID" means "same behaviour across binaries" for those four gates.

### 1.3 Provenance hashes

SHA-256 of the files this document relies on at generation time. If a hash differs when the
auditor checks it out, re-read the file before trusting a line number.

| File | SHA-256 |
|---|---|
| `stellereum/src/protocol.rs` | `8f0b3b34aa67b2c87da4c65c4db8395a56eb2211b6e9ab30c6401b5a722ab20a` |
| `stellereum/src/feature_gates.rs` | `b1694a3e3971de3e7907c9c49541312d6185dfadee2f9b12aac8824685f28fe1` |
| `stellereum/src/chain_spec.rs` | `49a2dbf8cffd4b470adade2a3b449ff686a76fed0ec5095eab4e827f5f5fce28` |
| `docs/feature_gates.yaml` | `2a95ec03c7a3a721154fa61d16cf1103a8d33d142ddbe8264cfd08a2247e05b5` |
| `docs/OPEN_DEFECTS.md` | `5bc3e0f9210cf18f638f168ad9f873b1b9bcddd6097ba0226cf55e4216bdff5c` |
| `stellereum/docs/FUZZING.md` | `8877478ef55900fcfb15785e3df9a7fcf06e355b456abd6401d9562fed27a2cf` |
| `docs/PERF_MATRIX.md` | `fd6380cea42a12c13232ea312b8c9dadd45fa794db2c5b01117954874e817566` |
| `docs/RELEASE.md` | `30ed35d8838720d048ca95599d719f1fd9da8fdc19c4c9e75d76a70db28a5d39` |
| `docs/RULESET_V7.md` | `19e5336fcc9a3280ab3eae7f36034e78080dee7299369fcf7dec67bb47d25ea0` |
| `stellereum/docs/specs/ACTIVATION_BATCH_1.md` | `52a09b7572eda81f254164387c99a794e08e305af00813e608c49b2ea20f1238` |
| `stellereum/src/bridge.rs` | `427f47bb2d68b2235b49dc04f461cef979a459bbeb8bc01ee6dcb1573f0b3c1c` |
| `stellereum/src/bridge_adapters.rs` | `dfeddd114dccb62069053a5c0b4e640ab7921e6f9ffd1b04c8b98dd4a25e9fb4` |
| `stellereum/src/pq_registry.rs` | `511d7cc72b8663042a3fa61f7fb2d0f58206134033e5f47fe376b48864d5a89f` |
| `stellereum/src/state_engine/mod.rs` | `64b24bb96305cdd603597ff12d7aa5c1daca48ded0bbcbdf3aa03b510b1371f4` |
| `stellereum/src/sharding/block.rs` | `6749088f7f24ddeb9df333516a115d9ba500e2bc735f3d2214c7551184ae6d57` |

---

## 2. Gate table

### 2.1 Status semantics

`stellereum/src/feature_gates.rs:36-44` defines:

* `ACTIVE` — constant is `0` (active from genesis);
* `INERT` — constant is `u64::MAX` (code exists, never fires);
* `SCHEDULED` — any other concrete height (active at/after `H`).

`chain_spec::ActivationGate` uses the same `u64::MAX` ↔ gated-off correspondence, asserted by
`gated_off_corresponds_strictly_to_u64_max` (`chain_spec.rs:1068-1099`). All gates use strict
`height >= H` semantics; `u64::MAX` is never active, including at `height == u64::MAX`.

The canonical source is **the constant**, not this document. The human/operator table is
`feature_gates::table()` (`feature_gates.rs:49-192`); the operator schedule is
`chain_spec::current_activation_schedule()` (`chain_spec.rs:890-1060`). The committed manifest
`docs/feature_gates.yaml` is generated from `table()` and pinned by
`committed_manifest_matches_the_table` (`feature_gates.rs:260-269`).

### 2.2 Canonical feature gates (`feature_gates.rs`)

`Pin` is the test named by the table row. `[WORKTREE]` = row absent at HEAD.
`table: MISSING` means the table itself declares no test; a candidate gate test is listed after
the semicolon where one exists in `stellereum/tests/`.

| ID | Constant | Value | Status | Pin | Pre-activation → post-activation invariant |
|---|---|---|---|---|---|
| `exec-hardening-v1` | `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | `tests/r1_frozen_apply_svm_tests.rs` | No gate boundary on this chain. Hardened VM execution is live: `Halt` barriers in block scanners, `SysCallCallContractArgs` / `SysCallSubmitPqPriceFeed` rollback, `TX_INTRINSIC_GAS = 280_000` floor, CLOB fill/cancel bounds. |
| `wasm-xshard-pmm-hardening` | `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | `tests/r1_wasm_hardening_tests.rs` | Live: `SubCallSnapshot` rollback, `caller()` vs `origin()`, outbound messages after `commit_native` with balance sync, `deploy_with_nonce(tx.nonce)`, PMM `ZeroMint`/`ZeroPayout`, canonical PQ1 decode. |
| `wasm-xshard-contract-send-refusal` | `WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT` | `0` | ACTIVE at 0 | `tests/review_final_cross_shard_contract_send.rs` | Live: a contract `host.send_message` to a non-local shard is refused before the debit (there is no authenticated delivery path; previously a burn). Same-shard delivery unchanged. |
| `wasm-table-elements-cap` | `WASM_TABLE_ELEMENTS_CAP_HEIGHT` | `u64::MAX` | INERT | table: `tests/w7_svm_and_contracts_fixes.rs` [WORKTREE]; at HEAD `MISSING`; candidate `tests/w4_engine_hardening_tests.rs` | Below `H`: consensus deploy/execute keeps uncapped WASM table acceptance for byte-identical replay; RPC pre-validation enforces the cap. At/above `H`: section-4 `Table` and wasmi `StoreLimits::table_elements` capped at `MAX_CONTRACT_TABLE_ELEMENTS = 16_384`. |
| `falcon-host-fuel-v2` | `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | `tests/w3_falcon_fuel_and_start_tests.rs` | Below: `host.falcon512_verify` charges `2_000` base fuel; legacy deploy validation/accounting. At/above: `150_000` base fuel; deploy validates once and charges actual `(start)` fuel to `state.gas_remaining`. |
| `contract-block-hash` | `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | table: `tests/w3_activation_boundary_e2e_tests.rs` [WORKTREE]; at HEAD `MISSING`; candidate `tests/activation_gate_contract_block_hash_tests.rs`, `tests/review_final_contract_block_hash.rs` | Below: `host.block_hash` succeeds and returns 32 zero bytes. At/above: returns the **parent** block hash (`block.prev_hash`), deterministic before execution. Single-tx / RPC preview still pass zero by design. |
| `bridge-target-address-cap` | `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` | `u64::MAX` | INERT | table: `tests/w3_activation_boundary_e2e_tests.rs` [WORKTREE]; at HEAD `MISSING`; candidate `tests/activation_gate_bridge_target_address_cap_tests.rs`, `tests/h9_bridge_target_address_cap.rs` | Below: no length cap; a 1 MiB `target_address` parks. At/above: `Withdraw.target_address.len() > 128` refused in `validate_at_height` and `plan_at_height` before rate-window/queue/balance. `Release`/`Refund` stay length-agnostic. |
| `xshard-bounce-escrow` | `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` | `u64::MAX` | INERT | table: MISSING; candidate `tests/activation_gate_xshard_bounce_escrow_tests.rs`, `tests/x8_bounce_escrow_gate.rs` | Below: legacy unconditional `produced_cross_shard` + 64-height timeout bounce. At/above: produced requires apply `status[i] == true` **and** committed XSHARD-01 escrow leaf; outbound legacy records need anchored escrow proof; bounce refused for a tx owning a §9 2PC record. Multi-shard `{0,1}` only; on live `{0}` it must stay `u64::MAX`. |
| `upgrade-exec` | `DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | `tests/upgrade_exec_gate_tests.rs` | Below: governance `SoftwareUpgrade` execution (exit 42) fails closed. At/above: on-chain plan installation and supervised execution. Effective value can come from the genesis chain spec (`chain_spec.rs:31-37`, `1101-1135`). |
| `actor-mailbox-hardening` | `ACTOR_MAILBOX_HARDENING_HEIGHT` | `u64::MAX` | INERT | `tests/w7_svm_and_contracts_fixes.rs` | Below: `try_deliver` and contract outbound routing keep legacy behaviour byte-for-byte. At/above: non-self `ActorSendBody` restricted to an allowlist and `ctx.balance = msg.value`; `host.send_message` budget capped at `MAX_CONTRACT_ACTOR_GAS_BUDGET = 1_000_000` and billed. |
| `sortition-unbiased` **[WORKTREE]** | `SORTITION_UNBIASED_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | `tests/w10_sortition_and_jail_gates_tests.rs` | Below: modulo reduction (`rand_val % total_power`). At/above: exact 64-bit rejection sampling in committee sortition and proposer selection. |
| `jail-budget-v2` **[WORKTREE]** | `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | `tests/w10_sortition_and_jail_gates_tests.rs` | Below: `DOWNTIME_MISS_THRESHOLD = 42`. At/above: `DOWNTIME_MISS_THRESHOLD_V2 = 200` (80 s at 400 ms). |
| `contract-abi-onchain` **[WORKTREE]** | `CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | `tests/w10_deploy_contract_abi_tests.rs` | Below: `OpCode::SysCallDeployContractWithAbi` (discriminant 65) reverts fail-closed. At/above: validates inline ABI (≤ `MAX_CONTRACT_ABI_BYTES`), deploys, persists `ContractAbi` into `ContractRegistry` / `state_root`, serves `stell_getContractAbi`. |
| `execution-pipeline-v1` **[WORKTREE]** | `EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | `tests/w12_pipeline_gate_tests.rs`, `tests/w12_pipeline_runtime_state_tests.rs` | Below: state-root binding lag 1 (`block(H).state_root` = post-state `H-1`). At/above: lag 2 (`H-2`), anchor `S+2` for post-state `S`, `VecDeque` `apply_in_flight`, `ApplyLane` penalty snapshots, `PendingExecView`, and lag-2 proposer/adopt/catchup gating. |

### 2.3 Schedule-only gates (`current_activation_schedule()`)

These appear in the operator schedule but not in `feature_gates::table()`. Their pin is the
schedule-vs-constants test `current_activation_schedule_matches_module_constants`
(`chain_spec.rs:1150-1301`), unless a more specific test is named.

| Constant | Value | Status | Pin | Invariant |
|---|---|---|---|---|
| `QC_SPLIT_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | schedule test | Below: legacy network-anchored `max(committee 2/3, network 2/3)` µQC rule. At/above: µQC is advisory-only; finality requires the full-network QC. |
| `BEACON_DRAW_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | schedule test | Below: parent-hash committee draw. At/above: epoch-bound XMSS-VRF beacon draw. |
| `CNVRF_V3_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | schedule test; `is_active_respects_boundaries_and_unknown_names` (`chain_spec.rs:1303-1341`) | Below: parent-hash draw. At/above: CN-VRF v3 epoch beacon sortition/proposer selection (legal heights restricted off epoch boundaries). |
| `COMPACT_GOSSIP_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test; `tests/compact_gossip_tests.rs` via `ci_local` suite | Compact bitfield micro-QC gossip codec is live from genesis; peers without the capability still receive full proposals. |
| `EMISSIONCapEXACT_ACTIVATION_HEIGHT` | `u64::MAX` | INERT | schedule test | Below: flat block emission `BLOCK_REWARD_NANO`. At/above: cap-exact geometric schedule. |
| `PQ_TRANSPORT_H_ACTIVATION_HEIGHT` | `10_000` | SCHEDULED at 10 000 | schedule test; `is_active_respects_boundaries_and_unknown_names` | Historical flag-day retained only for the frozen schedule. `is_pq_transport_active` is `true` at every height; the classical X25519 leg is deleted, so the height no longer selects a transport. |
| `XPC_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | `xpc_gate_matches_the_runtime_switch` (`chain_spec.rs:1343-1368`) | Cross-shard transfers use PREPARE→ACK→COMMIT from genesis; legacy one-way flow is refused at the target credit gate. |
| `HEADER_COMMIT_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test | Two-level `BlockHeader` v4; `state_root` and `prev_hash` bound into `block_hash`. |
| `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test | Canonical `Domain::EvmBindings` commitment and deterministic first-writer-wins apply; SnapV4 unit `271`. |
| `PQ_LIFECYCLE_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test | 3-key validator separation, Falcon-512 PoP, `next_seq` replay guard, explicit rotation cancel, 720 000-height evidence retention, 32-key hard cap. |
| `BRIDGE_V2_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test | Release requires a verified payout receipt; refund tombstones; every admitted deposit challengeable; retraction graded before confirm; committed height-indexed PQ keys. |
| `FEE_MARKET_V2_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test | `priority_fee_per_gas` charged in sequential/parallel/payload apply; exact block `u128` split (burn/proposer/staking). |
| `SUB_NANO_STRICT_ACTIVATION_HEIGHT` | `0` | ACTIVE at 0 | schedule test | Exact `wei_to_nano_exact` on EVM carrier boundaries, reward-accumulator rescale carry, 256-bit genesis mint, integer `eth_feeHistory`, committed Q0.64 emission carry. |

### 2.4 Activation invariants

All height-gated constants follow the same shape in `chain_spec` and `bridge.rs` / `pq_registry.rs`:

```text
active_at(h) = (constant != u64::MAX) && (h >= constant)
```

The guard `constant != u64::MAX` is explicit where the code compares `>=` (for example
`bridge_v2_active_at`, `stellereum/src/bridge.rs:324-327`) because `h >= u64::MAX` is true at
`h == u64::MAX`. Consequently an `INERT` gate is inert even at the top of the range
(`chain_spec.rs:1086-1098`). Below an activation height, every consumer must be byte-identical;
that is the replay invariant the auditor should test with a differential run at `H-1` and `H`.

### 2.5 Known inconsistencies in this snapshot (honest flags)

1. **`docs/feature_gates.yaml` updated for the worktree.** At HEAD `ab0adbf` both the
   table and the manifest had 10 rows. In the current worktree `docs/feature_gates.yaml`
   has been regenerated via `stellereum gates --yaml` to match all 14 rows in `feature_gates::table()`,
   and `committed_manifest_matches_the_table` passes.
2. **`docs/OPEN_DEFECTS.md` is stale for two v7 economics gates.** Its `FEE-PRIORITY-APPLY` row
   says `FEE_MARKET_V2_ACTIVATION_HEIGHT = u64::MAX` and its `FEE-SUBNANO-EXACT` row says
   `SUB_NANO_STRICT_ACTIVATION_HEIGHT = u64::MAX`. The code at HEAD has **both at `0`**
   (`stellereum/src/tokenomics.rs:251` and `:296`), and `docs/RULESET_V7.md:57-65` lists both as
   activated at 0. The code and RULESET_V7 agree; the defect registry text is stale.
3. **`docs/OPEN_DEFECTS.md` header names an older HEAD** (`c58375443`) than this snapshot
   (`ab0adbf`). Treat its statuses as of that older point unless re-confirmed in code.
4. **`feature_gates.yaml` note for `wasm-table-elements-cap`** still says "update
   `tests/w4_engine_hardening_tests.rs`"; the worktree row test is
   `tests/w7_svm_and_contracts_fixes.rs`. The note is not a consensus claim.
5. **Four [WORKTREE] gates are not in `FORK_ID_RULES`** (see §1.2). This is not a defect by
   itself, but it means the fork id does not attest to their armed/unarmed state.

---

## 3. Verification artefacts an auditor can rerun

These are the project's own gates. **None was executed for this handoff.** Run them from the
repository root unless a different `cd` is shown.

### 3.1 Core gate commands

| Command | What it proves | Recorded status in snapshot |
|---|---|---|
| `cargo fmt --all --check` | Formatting is canonical across the workspace. | Not run here. `ci_local.sh` stage `fmt` (`scripts/ci_local.sh:131-133`). |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` | No lint warnings in any target of the unified workspace. | Not run here. `ci_local.sh` stage `clippy` (`scripts/ci_local.sh:135-138`). |
| `cargo test --workspace --locked --lib` | Library unit tests for all 7 workspace crates. | Not run here. `ci_local.sh` stage `test-lib` (`scripts/ci_local.sh:140-143`). |
| `scripts/ci_local.sh --full` | Full local reproduction: fmt + clippy + lib + `scripts/test_parallel.sh -p stellereum`. Prints `CI_LOCAL_RESULT=PASS/FAIL`. | Not run here. Script is offline by default (`CARGO_NET_OFFLINE=true`, `scripts/ci_local.sh:17-21,55-56`). |
| `cargo audit` | RustSec advisory scan (independent second opinion to `cargo-deny`). | Not run here. CI wires `rustsec/audit-check` (`.github/workflows/ci.yml:224-233`); `docs/RELEASE.md:40-43`. |
| `cargo deny check` | `deny.toml` policy: advisories, licences, wildcard requirements, unknown registries. | Not run here. CI wires `EmbarkStudios/cargo-deny-action` (`.github/workflows/ci.yml:218`); `deny.toml` exists at the root. |

Copy-paste form:

```sh
cd /home/imm/stellereum-project
cargo fmt --all --check
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test --workspace --locked --lib
scripts/ci_local.sh --full
cargo audit
cargo deny check
```

`cargo audit` and `cargo deny` require their cargo subcommands to be installed
(`cargo install cargo-audit`, `cargo install cargo-deny --locked`); neither is a build step in
this repository. If the auditor's environment is offline, fetch the advisory database first.

### 3.2 Gate-pin suites

Run the suite named by the row, for example:

```sh
cd /home/imm/stellereum-project
cargo test --locked -p stellereum --test r1_frozen_apply_svm_tests
cargo test --locked -p stellereum --test r1_wasm_hardening_tests
cargo test --locked -p stellereum --test review_final_cross_shard_contract_send
cargo test --locked -p stellereum --test w3_activation_boundary_e2e_tests
cargo test --locked -p stellereum --test w3_falcon_fuel_and_start_tests
cargo test --locked -p stellereum --test w7_svm_and_contracts_fixes
cargo test --locked -p stellereum --test upgrade_exec_gate_tests
cargo test --locked -p stellereum --test activation_gate_bridge_target_address_cap_tests
cargo test --locked -p stellereum --test activation_gate_contract_block_hash_tests
cargo test --locked -p stellereum --test activation_gate_xshard_bounce_escrow_tests
cargo test --locked -p stellereum --test w10_sortition_and_jail_gates_tests
cargo test --locked -p stellereum --test w10_deploy_contract_abi_tests
cargo test --locked -p stellereum --test w12_pipeline_gate_tests
```

The schedule and manifest pins live in-unit:

```sh
cargo test --locked -p stellereum --lib chain_spec::tests
cargo test --locked -p stellereum --lib feature_gates::tests
```

`committed_manifest_matches_the_table` verifies `docs/feature_gates.yaml` matches `feature_gates::table()`.

### 3.3 Fuzzing (10 targets)

The harness is `stellereum/fuzz/`, a `cargo-fuzz` package excluded from the root workspace
(`Cargo.toml` `exclude`). It needs nightly and is not part of PR CI.

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd /home/imm/stellereum-project/stellereum
for t in frame_decode consensus_msg_decode transaction_decode block_decode \
         cert_envelope_decode evm_raw_tx_decode peer_msg_decode \
         vote_qc_decode rpc_json_decode falcon_sig_decode; do
  cargo +nightly fuzz run "$t" -- -max_total_time=60 -timeout=25 -rss_limit_mb=3072
done
```

Do not set `RUSTFLAGS`: cargo-fuzz selects the sanitizer and the matching flags
(`stellereum/docs/FUZZING.md:88-90`). Replay the committed corpus without mutation with
`cargo +nightly fuzz run <target> -- -runs=0`.

Targets and entry points are tabulated in `stellereum/docs/FUZZING.md:34-45`:
`frame_decode`, `consensus_msg_decode`, `transaction_decode`, `block_decode`,
`cert_envelope_decode`, `evm_raw_tx_decode`, `peer_msg_decode`, `vote_qc_decode`,
`rpc_json_decode`, `falcon_sig_decode`.

### 3.4 Throughput/latency matrix — **NOT YET RUN**

All **18 canonical cells** (`N ∈ {4, 32, 128}` × `offered ∈ {100, 1000, 5000} tx/s` ×
`STELL_MIN_BLOCK_MS ∈ {400, 250}`) are **`NOT MEASURED`** in this snapshot. The directory
`run/perf-matrix/20261125T163019Z/` exists but is empty: no `meta.json`, no `summary.md`, no
`cells/`. Nothing has been interpolated or copied from a non-matrix log; `docs/PERF_MATRIX.md`
forbids it.

The command that produces the rows is (from `docs/PERF_MATRIX.md:111-156`):

```sh
cd /home/imm/stellereum-project
STELL_MIN_BLOCK_MS=400 ./scripts/local-cluster.sh up 4

scripts/loadtest/loadtest/target/release/stell-loadtest \
  --allow-live --print-all-senders --url http://127.0.0.1:18646 --senders 128 \
  | tee /tmp/opencode/senders-128.txt

scripts/perf-matrix.sh \
  --local-cluster \
  --validators 4 \
  --block-floor-ms 400 \
  --i-know-this-is-not-mainnet \
  --rates 100,1000,5000 \
  --out run/perf-matrix/$(date -u +%Y%m%dT%H%M%SZ)
```

`--plan` renders the intended cells without touching a node. N=32/128 rows require a real
provisioned cluster of that size; a single-host mock is explicitly not acceptable evidence
(`docs/PERF_MATRIX.md:279-327`). Until such a run exists, no throughput or latency claim should be
made for this codebase.

### 3.5 Recorded baselines (quoted, not re-run)

These are the project's most recent recorded results. They are **not** a substitute for the
commands above, and they are not evidence about the dirty worktree.

| Evidence | Recorded result | Source |
|---|---|---|
| 10-target fuzz baseline (2026-11-25) | 23,550,124 total executions, 0 crashes, 0 panics, 0 OOMs; per-target table in source | `stellereum/docs/FUZZING.md:177-195` |
| Wave 8 gate (2026-11-25) | `cargo fmt --all --check` clean; `cargo clippy --workspace --locked --all-targets -- -D warnings` 0/0; `stellereum --lib` 1527/1527; `--bins` 113/113; `consensus_liveness_harness` 13/13; `stellereum-upgrader` 27/27 | `docs/OPEN_DEFECTS.md:403-409` |
| Ruleset v7 R5 deployment | 8 v7 gates active at 0; full `stellereum` gate 399/399; `clippy` 0/0; 4/4 validators at 2000 STELL, `fragile: false` | `docs/OPEN_DEFECTS.md:251` |
| PQ transport/DKG baseline | `w8_cnvrf_and_mev_hardening_tests` 15/15 | `docs/OPEN_DEFECTS.md:407` |

---

## 4. Honest limitations

### 4.1 Assurance and architecture

* **Single-client monoculture.** There is exactly one Rust consensus implementation. A
  second independent client is explicitly deferred as `SYS-SECOND-CLIENT`
  (`docs/OPEN_DEFECTS.md:382`, `docs/STELLEREUM_VS_SOLANA_TON.md:95`). Differential testing
  against another implementation does not exist. A client bug can therefore be a chain bug.
* **No completed external audit.** The repository has internal reviews and a comprehensive
  internal report (`docs/audits/COMPREHENSIVE_AUDIT_REPORT.md`), but no independent external
  security audit has been completed (`docs/STELLEREUM_VS_SOLANA_TON.md:95`). This handoff is
  preparation for one, not the audit itself.
* **Testnet scale is 4 validators.** The live public testnet runs `A/B/C/D` at shard `0`, with
  shard `1` parked (`docs/STELLEREUM_VS_SOLANA_TON.md:9`). Nothing here proves behaviour at
  N=32/128. Consensus message count, vote/QC verification, fan-out and CPU contention all change
  with N (`docs/PERF_MATRIX.md:279-286`).
* **Operational incident history.** `docs/OPEN_DEFECTS.md:24-96` records a ~8-hour halt on
  2026-11-24 caused by a degenerate bootstrap validator set and an unverifiable self-final
  precommit-QC. The code fix is deployed and the RCA is closed, but persistent/restorable
  validator-set history (or deriving the set at `H` from the `H-1` snapshot) remains open. An
  auditor should treat validator-set resumption as an active risk area, not a finished one.

### 4.2 Unmeasured performance

The 18-cell perf matrix is `NOT MEASURED` (§3.4). There is no measured throughput, inclusion
latency, apply-time percentile, CPU-per-block, or BFT-finality number in this snapshot. Any
capacity statement about this codebase is `UNVERIFIED`.

### 4.3 Deferred `stell-wallet` findings

`docs/OPEN_DEFECTS.md:400-401` defers seven wallet findings from Wave 6:
`W6-A6-1` (SPV leaf decode), `W6-A6-2` (`pq-transfer` chain binding), `W6-A6-5` (stealth
plaintext fallback), `W6-A6-7` (`faucet_token` HTTP check), `W6-A6-8` (zeroization),
`W6-A6-10` (fake `aa` commands), `W6-A6-11` (local-sim overflow/permissions).

What is verifiable in this snapshot:

* The **worktree** contains uncommitted wallet changes and three new wallet test files
  (`w9_wallet_hardening_tests.rs`, `wallet_aa_revoke_tests.rs`,
  `wallet_full_pq_regression_tests.rs`). The hardening test explicitly names
  `W6-A6-1`, `W6-A6-5`, `W6-A6-7`, `W6-A6-10`, `W6-A6-11` in its header
  (`stell-wallet/tests/w9_wallet_hardening_tests.rs:1-7`).
* `W6-A6-2` (chain binding) and `W6-A6-8` (zeroization) appear addressed in
  `stell-wallet/src/main.rs` (`resolve_sign_chain_id`, `zeroize::Zeroizing` usage), but no
  dedicated passing test was identified for those two in this read-only pass.
* **`stell-wallet` verification status:** `stell-wallet` is excluded from the root workspace
  (`Cargo.toml` `exclude`), so the root `--workspace` gate does not cover it; however,
  `cargo test --manifest-path stell-wallet/Cargo.toml --locked --offline` was executed separately
  and all wallet test targets passed with 0 failures (an auditor should still review the diff and
  rerun `cd stell-wallet && cargo test` independently).

### 4.4 Contracts are demo-grade

The four reference programs still expose **legacy packed-`i64` entrypoints** that are explicitly
`DEMO-GRADE` compatibility shims. Every program header says "DO NOT deploy with value without a
full audit":

* `account-object`: `init`, `transfer_ownership`, session entrypoints use integer ids
  (`stellereum-contracts/contracts/account-object/src/lib.rs:2-15`).
* `liquidity-pool`: `deposit`, `withdraw`, `shares_of` (`.../liquidity-pool/src/lib.rs:2-10`).
* `stl-dns`: `init`, `start_auction`, `place_bid`, `finalize_auction`, `resolve`, `set_target`,
  `transfer` (`.../stl-dns/src/lib.rs:2-12`).
* `sts20-token`: `init`, `transfer`, `transfer_from`, `approve`, `mint`, `burn`, `balance_of`,
  `allowance` (`.../sts20-token/src/lib.rs:2-11`).

Real **32-byte post-quantum `*_pq` entrypoints now exist** and authenticate the 32-byte
`host.caller` / Falcon-512 wallet identity, for example `init_pq`, `transfer_pq`,
`transfer_from_pq`, `approve_pq`, `mint_pq`, `burn_pq` in `sts20-token`
(`.../sts20-token/src/lib.rs:467-764`) and the `*_pq` variants in the other three programs;
contracts initialized via `init_pq` also set `SLOT_PQ_MODE` to lock out unauthenticated legacy
entrypoints. `stellereum-sdk` now includes `TxIntent::ContractDeploy` alongside `Op::DeployContract` /
`Op::DeployContractWithAbi`. The existence of the PQ entrypoints does **not** upgrade the contracts'
assurance status: the repository still says demo-grade, no external audit, and no in-place upgrade
(`stellereum-contracts/README.md:12-30,280-292`).
`CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` is `u64::MAX`, so on-chain ABI persistence is not armed.

### 4.5 Inert gates that still leave a known vector open on-chain

An `INERT` gate means the mitigation exists in code but is **not enforced by consensus**. These
are the material ones:

| Gate (INERT) | Vector still open at the current chain height |
|---|---|
| `WASM_TABLE_ELEMENTS_CAP_HEIGHT` | A consensus deploy/execute of a module declaring a huge section-4 `Table` is not capped; only RPC pre-validation refuses it. A block producer can still include such a module on-chain. |
| `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT` | `host.falcon512_verify` still charges `2_000` base fuel, so a transaction can buy many verifications per block; deploy still has the legacy double-validation / `(start)` accounting gap. |
| `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` | `host.block_hash` still returns 32 zero bytes. Not a fund-loss vector, but any contract that treats zero as a sentinel can be misled. |
| `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` | `Withdraw.target_address` is still unbounded on-chain (only non-empty is checked). An attacker can park arbitrarily large strings in `pending_withdrawals` for zero bridge value (state-growth DoS). `Release`/`Refund` also never inspect length. |
| `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` | On a multi-shard `{0,1}` chain, the legacy bounce path can refund value that was never escrowed, and the §9 2PC/legacy double-spend remains possible. **Unreachable on live `{0}`**, but a hard blocker for unparking shard 1. |
| `ACTOR_MAILBOX_HARDENING_HEIGHT` | Non-self `ActorSendBody` delivery can still execute asset-debiting/state-mutating opcodes and see the recipient's full balance; contract `host.send_message` `gas_budget` is not capped/billed. |
| `SORTITION_UNBIASED_ACTIVATION_HEIGHT` | Committee/proposer draws still use modulo reduction; non-power-of-two stake totals retain a selection bias. |
| `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` | Downtime jailing still uses 42 misses = 16.8 s at 400 ms. Mitigated operationally by `scripts/auto-unjail.sh`, not by consensus. |
| `CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` | Opcode 65 is unavailable; no ABI manifest is committed with a deploy. Feature-off, not a direct vector. |
| `EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT` | State-root binding stays lag 1; the lag-2 path is not armed. Feature-off, not a direct vector. |
| `QC_SPLIT_ACTIVATION_HEIGHT`, `BEACON_DRAW_ACTIVATION_HEIGHT`, `CNVRF_V3_ACTIVATION_HEIGHT`, `EMISSIONCapEXACT_ACTIVATION_HEIGHT` | Legacy rules stay live: network-anchored µQC, parent-hash draw (grindable, documented), flat emission. These are documented residuals, not hidden ones. |
| `UPGRADE_EXEC_ACTIVATION_HEIGHT` | On-chain upgrade execution fails closed at every height. Safe, but the upgrade path is unavailable on-chain. |

`PQ_TRANSPORT_H_ACTIVATION_HEIGHT = 10_000` is **not** an inert security gate: the classical
transport is deleted and PQ transport is active at every height.

### 4.6 Documentation drift

The auditor should not trust prose over code. Known drift in this snapshot:

* `docs/feature_gates.yaml` is a generated artifact pinned to `feature_gates.rs`; it has been
  regenerated for the updated worktree (§2.5) via `stellereum gates --yaml`.
* `docs/OPEN_DEFECTS.md` names HEAD `c58375443`, not `ab0adbf`, and two economics-gate statuses
  contradict the code (§2.5).
* The original `docs/BRIDGE_THREAT_MODEL.md` pin is 2026-11-20; its `file:line` citations for
  `bridge.rs` are stale after Ruleset v7. A dated addendum was appended on 2026-11-26 and the
  original body is left byte-intact. Use the addendum for current line numbers.
* `docs/STELLEREUM_VS_SOLANA_TON.md` says the contracts have only legacy entrypoints in some
  places while the contract sources now expose `*_pq` entrypoints; the comparison's assurance
  conclusion (demo-grade, no external audit) remains correct.

### 4.7 What this snapshot does not cover

* No live-cluster query was made. Heights, peer counts, jail state, validator power and the
  current live bridge state are `UNVERIFIED` here.
* No transaction was submitted, no key was touched, no store was read beyond source files.
* No claim is made about foreign-chain contracts, the TON/EVM/Arbitrum/Solana bridges, or any
  relayer daemon: those are outside this repository.

### 4.8 Bridge `Deposit`+`Attest` key resolution (`BRIDGE-PQ-HEIGHT-KEY`)

*Note (updated 2026-11-26):* The plain `Deposit` + `Attest` quorum path in `BridgeState::plan_at_height`
previously delegated to `TeleportBridgeEngine::process_deposit` -> `verify_quorum_signatures`
at `attestation_height = 0` with `PreV2ConsensusLookup`. In the current worktree, `plan_at_height`
is wired to height-indexed committed key verification at/after `BRIDGE_V2_ACTIVATION_HEIGHT = 0`
and pinned by `stellereum/tests/w16_bridge_deposit_height_key_tests.rs` (5/5 passing tests covering
key rotation forgery rejection and new-key acceptance alongside legacy `process_deposit` parity).

---

## 5. Threat-model trust boundaries

### 5.1 Light clients: the validator set is an out-of-band anchor

A light client's trust root is the validator set, pinned **out of band**. A set handed to you by
the server you are verifying is explicitly *not* an anchor
(`docs/LIGHT_CLIENT_VERIFY.md:4-30`). The CLI refuses to proceed without the pinned set
(`stellereum/src/light_client_cli.rs:8-48,511-514`). The anchor is the pair `(set, height)`;
rotation is accepted only through `LightClient::rotate_validator_set`, and the replacement set's
contents are pinned out of band exactly like the genesis set
(`light_client_cli.rs:37-48`, `docs/LIGHT_CLIENT_VERIFY.md:71-100`).

Consequences for the auditor:

* The server cannot choose its own verifiers. If the pinned set is wrong, every downstream
  verification is wrong; there is no weak-subjectivity checkpoint convention beyond the pinned
  file.
* Finality is **precommit-QC only**; a prevote QC is refused (`docs/LIGHT_CLIENT_VERIFY.md:46-54`).
* The header a proof is checked against is the first header a quorum certified for the root, at
  exactly `height + 1`; `--min-height` prevents anchoring on an old height
  (`light_client_cli.rs:411-431`).

### 5.2 Safety assumption: Byzantine power `B < W/3`

The consensus safety argument is the standard BFT one: `floor(2W/3)+1` quorum, and safety holds
only while Byzantine voting power is **less than one third** of total power
(`stellereum/docs/audits/EXTERNAL_AUDIT_BRIEF.md:207`,
`stellereum/docs/audits/THREAT_MODEL.md:191,219`). The µQC adds a network-anchored floor
(`max(2/3 committee, 2/3 network)`) and the mixed-pair condition `t_µ + t_f − W > B`; it does not
remove the `B < W/3` assumption.

At `B ≥ W/3` the protocol may lose liveness or safety; no code check can prevent that. The live
testnet is 4 validators: one Byzantine validator is `W/4 = 0.25W` (below 1/3), while two are
`W/2 = 0.5W` (above it). The safety claim is a protocol assumption, not an empirical result about
the current operator set.

### 5.3 PQ-only cryptography assumption

The chain claims full post-quantum cryptography end to end
(`docs/STELLEREUM_VS_SOLANA_TON.md:28-34`):

* transactions and consensus votes/QCs are Falcon-512 (FIPS 206) in canonical PQ1 envelopes;
* P2P key exchange is ML-KEM-768 (FIPS 203) with Falcon frame authentication;
* classical Ed25519/BLS vote lanes are deleted;
* validator custody uses 3-key separation with a cold `withdrawal_address` and `RemotePqSigner` v2.

Trust boundary: there is **no classical fallback**. If a PQ primitive is broken, misimplemented,
or the Falcon verification path is confused, there is no second signature lane to fall back to;
the code fails closed. ML-DSA-44 is present as an enum/size but disabled fail-closed (no
verifier) (`stellereum/src/pq_registry.rs:160-170`). The auditor should treat "PQ-only" as both a
strength (no downgrade) and a single point of failure (one primitive family, one implementation).

### 5.4 Non-consensus surfaces

These surfaces can lie, censor, or leak, but cannot by themselves change finalized consensus
state unless they also hold validator keys:

| Surface | Trust boundary | What a compromise can do | What it cannot do |
|---|---|---|---|
| **RPC** (`stell_*`, `eth_*` reads/writes, WS/SSE) | Untrusted client-facing; rate-limited, but the node is authoritative for what it serves. | Return stale/false reads, censor submissions, leak query patterns, fill logs. | Forge a finalized block or a QC without validator keys; alter another node's state. |
| **Faucet** | Hot-key service, not consensus. | Drain its own funded key within caps; refuse service; lie about a drip. | Mint outside the faucet's funded balance; change supply accounting. |
| **Relayer / bridge external leg** | 2/3 Falcon quorum plus an off-chain payout process; no daemon in this repo. | Withhold or duplicate a foreign payout if its own journal/dedup is wrong; censor a claim. | Move native escrow without a committed `BridgeIntent`; bypass `ReleaseProof` at/after `BRIDGE_V2_ACTIVATION_HEIGHT = 0`. |
| **Indexer** (`stellereum-indexer/`) | Derived SQLite view; reorg-aware but not consensus. | Serve a lagged or reorged view; wrong cursors/stats. | Change the chain's state root or finality. |
| **Explorer / gateway** (`explorer-site/`, `stellereum/src/explorer.rs`) | Presentation + HTTP gateway; own rate limits and cache. | Show wrong data, break `/readyz`/metrics, proxy abuse. | Forge consensus; the gateway is not a validator. |

The bridge deserves a special note: at `BRIDGE_V2_ACTIVATION_HEIGHT = 0`, the **native** release
authorization, replay guard, refund tombstone and challengeability are consensus code. The
**foreign** payout is still an off-chain relayer action with no light client; its trust root is
the same 2/3 validator quorum, not a foreign-chain proof
(`docs/BRIDGE_THREAT_MODEL.md:35-82`; addendum 2026-11-26).

### 5.5 Bridge-specific boundary summary

* Inbound deposit: 2/3 distinct Falcon keys — but the plain `Attest` path still resolves those
  keys through the process-global mirror at height 0 rather than the passed committed lookup
  (§4.8) — or adapter "evidence" that still reduces to a quorum-signed header. The leaves are
  Stellereum's own encodings, not foreign events.
* Outbound release: at/after v7, a bare `Release` fails closed; a verified `ReleaseProof` binds
  `(req_id, chain, address, amount, external_tx_hash, finalized_head, attestation_height)` and the
  quorum signs it. A refund writes a tombstone so a late proof fails loudly.
* Disputes: every admitted deposit is challengeable at/after v7; a quorum `RETRACTION` is graded
  before any confirm evidence. A challenge still cannot claw back funds the recipient already
  spent (`docs/BRIDGE_THREAT_MODEL.md:884-916`; unchanged).
* No foreign light client, no header linkage to a committed anchor, no inbound timeout, no
  per-deposit validator-set snapshot, and no pruning of resolved disputes. These remain the
  structural gaps (§4.5 and the bridge addendum).

---

## 6. Suggested auditor order of work

1. Recompute `FORK_ID` from `protocol.rs` inputs and confirm `0x3ae00ebc`; confirm the 32 rules
   and 16 domains are exactly the reviewed bytes.
2. Read `chain_spec::current_activation_schedule()` and `feature_gates::table()`; reconcile every
   row against the constant it names (not against this document).
3. Run the core gate (§3.1) on a **clean** checkout of `ab0adbf`; then run it on the updated tree
   and explain any delta. The updated tree adds four gates and the Wave 9–16 / post-audit fixes,
   with `docs/feature_gates.yaml` regenerated to match all 14 gates.
4. Run the gate-pin suites (§3.2), with special attention to the `u64::MAX` boundary tests and
   the `H-1` / `H` differential replay.
5. Re-run the fuzz corpus and at least one mutation run per target (§3.3).
6. Treat the 18-cell perf matrix as empty until a real run exists (§3.4).
7. Review the bridge addendum and the current `plan_at_height` / `resolve` arms; do not trust the
   2026-11-20 line numbers.
8. Review the wallet workspace separately; it is outside the root workspace gate.
9. Review the contracts as demo-grade reference code, not as audited financial infrastructure.

---

## 7. Source index

Consensus identity and gates:

* `stellereum/src/protocol.rs` — `PROTOCOL_VERSION`, `CONSENSUS_RULESET_VERSION`,
  `DOMAIN_SET_VERSION`, `FORK_ID_RULES`, `derive_fork_id`, `FORK_ID`.
* `stellereum/src/feature_gates.rs` — canonical gate table and manifest generator.
* `stellereum/src/chain_spec.rs` — gate constants, helpers, `current_activation_schedule()`.
* `docs/feature_gates.yaml` — generated manifest (stale in the dirty worktree).
* `docs/RULESET_V7.md`, `docs/RULESET_V2.md` … `docs/RULESET_V6.md` — ruleset history.
* `stellereum/docs/specs/ACTIVATION_BATCH_1.md` — A1–A9 pre/post invariants and arming
  prerequisites.

Operational evidence:

* `docs/OPEN_DEFECTS.md` — defect registry, including Wave 6–8 closure and deferred wallet work.
* `stellereum/docs/FUZZING.md` — 10 targets, entry points, 2026-11-25 baseline.
* `docs/PERF_MATRIX.md` — 18-cell method, evidence rules, `NOT MEASURED` policy.
* `docs/RELEASE.md`, `.github/workflows/release.yml` — `--locked` build, SHA-256, SPDX SBOM,
  keyless cosign (`.sig`/`.pem`), verification commands.

Comparison and trust model:

* `docs/STELLEREUM_VS_SOLANA_TON.md` — scope/evidence basis, residual gaps, non-measured cells.
* `docs/LIGHT_CLIENT_VERIFY.md`, `stellereum/src/light_client_cli.rs` — out-of-band anchor.
* `stellereum/docs/audits/EXTERNAL_AUDIT_BRIEF.md`, `stellereum/docs/audits/THREAT_MODEL.md` —
  `B < 1/3` safety assumption and quorum trust.
* `docs/BRIDGE_THREAT_MODEL.md` + addendum 2026-11-26 — bridge trust boundaries.

Contracts:

* `stellereum-contracts/README.md` and `stellereum-contracts/contracts/*/src/lib.rs` —
  `DEMO-GRADE` status, legacy packed-`i64` entrypoints, `*_pq` entrypoints.
