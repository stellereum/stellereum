# Protocol upgrades and disaster recovery — verified as-is, design proposal, runbook

**Baseline.** Originally read at `HEAD = be52ce87c` (2026-11-17/18). **Updated
2026-11-19 for `24e2a1dca` (mega-wave `3f4b80e16..24e2a1dca`)** where noted: compact
gossip, block-carried governance, 2PC and catch-up changed. Every `file:line` below is a
line in the read tree; anything that could not be proven from the tree or a pasted command
is marked **UNVERIFIED**.

Scope of the question: *how does an operator safely upgrade the protocol and recover from
disaster today?* This document answers that for the live 4-validator topology in
`scripts/cluster-nodes.conf:19-47` (nodes A–D, single shard 0, quorum 3-of-4).

---

## 0. TL;DR

1. **On-chain governance works; only binary execution is still gated.** The
   block-carried gate is `GOV_OPS_ACTIVATION_HEIGHT = 0`
   (`stellereum/src/governance.rs:151`): signed `SysCallGovPropose` /
   `SysCallGovVote` transactions apply on every node, and the deterministic sweep
   finalizes due proposals and executes every matured `GovAction` in ascending id
   order (`apply_gov_ops` / `apply_governance_transition`,
   `stellereum/src/state_engine/apply.rs`). The direct RPC form remains solo-only
   and still refuses on `validator_set.len() > 1`
   (`stellereum/src/governance.rs:1082+`), so multi-node governance uses the
   block form. **The remaining blocker is `SoftwareUpgrade`/`CancelUpgrade`
   execution:** those actions additionally require
   `UPGRADE_EXEC_ACTIVATION_HEIGHT` (`stellereum/src/governance.rs:80`), still
   `u64::MAX`, so a passed upgrade proposal stays `Passed` and never installs
   `AppliedParams::upgrade_plan`. The halt-on-upgrade code in
   `stellereum/src/node/consensus_driver.rs:3112-3200` is therefore reachable
   only after that second gate is ratified.
2. **Every real gate is a compile-time constant inside a binary**, so "flipping a height"
   is always a coordinated binary swap. One exception is worse: the only *env*-driven
   consensus gate, `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`, is read inside the apply path
   (`stellereum/src/state_engine/parallel.rs:804`,
   `stellereum/src/node/consensus_driver.rs:1555`) — a per-node env edit is a fork window,
   not a config change.
3. **Mixed versions fail closed, never silently fork** — with three caveats: `FRAME_VERSION`
   is exact-match `2` with no negotiation (`infnode/crates/infnode/src/proto.rs:137,266`),
   the consensus `ValidatorId` is still the Ed25519 key while vote validity is Falcon-only
   (`stellereum/src/consensus/types.rs:1095-1107,1181-1183`), and the executed
   `upgrade_plan` is **not** in the commitment digest (`stellereum/src/commitment.rs:726-757`
   has no `upgrade_plan` arm), so the trigger is local, uncommitted state.
4. **The recovery mechanism has a hard, provable deadlock.** A caught-up node restores a
   snapshot at height `B` and then refuses any body walk longer than **256** blocks
   (`stellereum/src/node/sync.rs:698`), while consecutive snapshots can be up to
   `snap_int + 100 = 1100` blocks apart (`stellereum/src/snapshot_cadence.rs:29,79-82`,
   default `snap_int = 1000` at `stellereum/src/node/policy.rs:246-252`). On a **live**
   chain this is a bounded wait for the next snapshot; on a **halted** chain (two of four
   validators lost) the next snapshot never comes, so the chain cannot self-recover and a
   filesystem backup is mandatory.
5. **`COMMITMENT_VERSION` is 5** (`stellereum/src/commitment.rs:100`). Any bump forces a
   genesis reset — the code itself says "every data directory needs a wipe"
   (`stellereum/src/commitment.rs:93-98`). That is the line between an in-place upgrade and
   a new chain.
6. **Rollback is supported only before the halt height.** After it, finalized blocks cannot
   be rewound; restoring a pre-upgrade data directory puts the node behind a chain its old
   binary cannot validate. The only "rollback" is a coordinated new genesis.

---

## 1. Verified as-is

### 1.1 Inventory of every `*_ACTIVATION_HEIGHT` gate

`rg -n "pub const \w*ACTIVATION_HEIGHT\s*:\s*u64\s*=" stellereum/src infnode/crates` (pasted):

```
stellereum/src/consensus_net.rs:2097:pub const COMPACT_GOSSIP_ACTIVATION_HEIGHT: u64 = 0;
stellereum/src/xshard2pc.rs:146:pub const XPC_ACTIVATION_HEIGHT: u64 = 0;
stellereum/src/governance.rs:151:pub const GOV_OPS_ACTIVATION_HEIGHT: u64 = 0;
stellereum/src/mev_epoch.rs:995:pub const PQ_TRANSPORT_H_ACTIVATION_HEIGHT: u64 = 10_000;
stellereum/src/mev_epoch.rs:1703:pub const MEV_RESHARE_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/consensus/sortition.rs:179:pub const QC_SPLIT_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/consensus/sortition.rs:539:pub const BEACON_DRAW_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/consensus/sortition.rs:650:pub const CNVRF_V3_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/governance.rs:80:pub const UPGRADE_EXEC_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/tokenomics.rs:55:pub const EMISSIONCapEXACT_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/oracle.rs:205:pub const SPRT_TIER3_ACTIVATION_HEIGHT: u64 = u64::MAX;
stellereum/src/chain_binding.rs:48:pub const CHAIN_BINDING_ACTIVATION_HEIGHT: u64 = CHAIN_BINDING_NEVER;
stellereum/src/zkml_attestation.rs:144:pub const ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT: u64 = u64::MAX;
```

Thirteen constants (one env-adjacent `CHAIN_BINDING_NEVER` is the explicit never sentinel;
`DEFAULT_BLS_ACTIVATION_HEIGHT` quoted in `docs/specs/02_CRYPTO_AND_PQ_PHASE2.md:56` has
**no code declaration** and is a docs-only name, not a gate).

| # | Gate | Value | Declared | Reader / effect | Flip requires |
|---|------|-------|----------|-----------------|---------------|
| 1 | `QC_SPLIT_ACTIVATION_HEIGHT` | `u64::MAX` | `consensus/sortition.rs:179` | `qc_split_active_at` (`:215-225`); used by `consensus/types.rs:1677,1823,2057` and `consensus/qc_split.rs` | **Binary swap.** Test/debug-only thread override (`sortition.rs:191-213`); release builds have none |
| 2 | `BEACON_DRAW_ACTIVATION_HEIGHT` | `u64::MAX` | `consensus/sortition.rs:539` | `beacon_draw_active_at` (`:548-556`); parent-hash draw stays canonical | **Binary swap.** No env, no override |
| 3 | `CNVRF_V3_ACTIVATION_HEIGHT` | `u64::MAX` | `consensus/sortition.rs:650` | `cnvrf_v3_active_at` (`:666-674`); epoch length 7 200 | **Binary swap.** Test-only instance override exists |
| 4 | `COMPACT_GOSSIP_ACTIVATION_HEIGHT` | `0` | `consensus_net.rs:2097` | `compact_gossip_gate` / `compact_gossip_active`; proposal path wired in the node (`proposal_gossip_msg`, `CompactReceiver`, `CompactBodyServer`) | **Active from genesis.** Compact µQC emit/admit call sites are still deferred, so finality uses the full `Committed` envelope |
| 5 | `EMISSIONCapEXACT_ACTIVATION_HEIGHT` | `u64::MAX` | `tokenomics.rs:55` | `calculate_block_reward_at_height` | **Binary swap.** Changes consensus state from the activation height |
| 6 | `PQ_TRANSPORT_H_ACTIVATION_HEIGHT` | `10_000` | `mev_epoch.rs:995` | `is_pq_transport_active` (`:1003-1006`) returns `true` unconditionally | **Nothing.** Retained only for the frozen schedule (`:990-994`) |
| 7 | `XPC_ACTIVATION_HEIGHT` | `0` | `xshard2pc.rs:146` | `XpcActivation::from_chain_spec` (`:327-342`) | **Active from genesis.** Env `STELL_XPC_ACTIVATION_HEIGHT` is deprecated, logged and **ignored** (`node/policy.rs:1016-1047`) |
| 8 | `MEV_RESHARE_ACTIVATION_HEIGHT` | `u64::MAX` | `mev_epoch.rs:1703` | `is_reshare_active` (`:1714-1717`), `runtime/mev_sync.rs:357` | **Binary swap.** Not registered in `chain_spec` |
| 9 | `GOV_OPS_ACTIVATION_HEIGHT` | `0` | `governance.rs:151` | `gov_ops_active_at`; `apply_gov_ops` + deterministic `apply_governance_transition` (`state_engine/apply.rs`) | **Active from genesis.** Block-carried propose/vote and finalize/execute run on every node. Still not registered in `chain_spec` |
| 10 | `SPRT_TIER3_ACTIVATION_HEIGHT` | `u64::MAX` | `oracle.rs:205` | `sprt_tier3_active_at` (`:223-227`) | **Binary swap.** Not in `chain_spec` |
| 11 | `UPGRADE_EXEC_ACTIVATION_HEIGHT` | `u64::MAX` | `governance.rs:80` | `upgrade_exec_active_at`, `due_governance_ids` | **Binary swap.** Separate gate: `SoftwareUpgrade`/`CancelUpgrade` execute only when this is open; not in `chain_spec` |
| 12 | `CHAIN_BINDING_ACTIVATION_HEIGHT` | `CHAIN_BINDING_NEVER` | `chain_binding.rs:48` | `check_admission*` | **Binary swap.** Retire the env form (§4 item 11) |
| 13 | `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` | `u64::MAX` | `zkml_attestation.rs:144` | context-bound attestation transcript | **Binary swap.** Opt-in seam, not in `chain_spec` |

The consolidated registry `chain_spec::current_activation_schedule()` lists only seven of
these (`stellereum/src/chain_spec.rs:130-180`): QC split, beacon draw, CN-VRF v3, compact
gossip, emission, PQ transport, XPC. **Missing from the registry: `MEV_RESHARE`,
`GOV_OPS`, `SPRT_TIER3`, `UPGRADE_EXEC`, `CHAIN_BINDING`, `ZKML_CONTEXT_BINDING`** — an
operator inspecting "the schedule" cannot see the gate that still blocks
`SoftwareUpgrade` execution, even though governance itself is active.

#### Runtime (environment) switches that also change consensus

| Env | Default | Read where | Is a "pure config change" safe? |
|---|---|---|---|
| `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` | unset = never (`u64::MAX`) | `chain_binding.rs:33,66-78`; **inside apply**: `state_engine/parallel.rs:804`, `node/consensus_driver.rs:1555` | **No.** Each node reads its own env per block; one node with `H`, one without, disagrees on which transactions are admissible. This is the exact anti-pattern `STELL_XPC_ACTIVATION_HEIGHT` was retired for (`node/policy.rs:858-881`). **UNVERIFIED** whether a live deployment currently sets it (`multinode/nodeB/env.B` does not) |
| `STELL_XPC_ACTIVATION_HEIGHT` | ignored | `node/policy.rs:872-881` | No-op with a loud WARN |
| `STELL_VRF_ACTIVATION_HEIGHT` | removed | `rg -n "VRF_ACTIVATION" stellereum/src` → no hits | Stale docs only (`docs/specs/00_PROJECT_MAP_PHASE2.md:20`, `stellereum/docs/PLAN-VRF.md:5`) |
| `STELL_AUTO_UPGRADE` | unset = disarmed | `governance.rs:676-706`; banner `node/bootstrap.rs:455-481`; trigger `node/consensus_driver.rs:2911` | Node-local by design; must be identical on every node or none (`docs/OPERATIONS.md:1449-1452`) |
| `STELL_SHARDS`, `STELL_CHAIN_ID`, `STELL_FAUCET_KEY`, `STELL_PURE_PQ` | deployment-specific | `scripts/local-cluster.md:34-46` documents them as genesis/topic inputs | **No.** They change the genesis root, the epoch/topic or the verification predicate |

### 1.2 Upgrade / halt machinery

#### 1.2.1 What exists

- `GovAction::SoftwareUpgrade { name, height, sha256 }` (`stellereum/src/governance.rs:207-213`)
  validates a non-empty name, a non-zero height, a non-zero digest and a safe path segment
  (`:320-345`). Execution stores it in `applied.upgrade_plan`
  (`:1812-1830`); `CancelUpgrade` clears it (`:1831-1833`).
- Timing is deterministic: proposals open for `GOVERNANCE_VOTING_PERIOD_SECS` (3 days,
  `:36`), need `PROPOSAL_MIN_STAKE_NANO` (10 000 STELL, `:38`), and a passed action is
  timelocked for `GOV_TIMELOCK_HEIGHTS = 7_200` (`:60`). Note the comment "≈ 6 h at 3 s
  blocks" (`:48-50`) does not match the live 50 ms block floor
  (`node/policy.rs:356`, `node/consensus_driver.rs:893-901`): 7 200 heights is ≈ 6 minutes
  at 50 ms.
- The trigger is on the finalize lane: `if plan.height <= height` →
  `request_flush`, `snapshot_state`, `snapshot_domains`, then optional `execve` and
  `std::process::exit(42)` (`node/consensus_driver.rs:3129-3200`).
- `STELL_AUTO_UPGRADE` arms an in-place `execve` of the SHA-256-verified staged binary
  (`governance.rs:751-830`). Staging is hardened: safe name, regular file, no symlinked
  file or parent, ≤512 MiB, exact digest, private 0700 copy of the hashed bytes
  (`governance.rs:756-830`; summary in `docs/OPERATIONS.md:1466-1520`).

#### 1.2.2 What works now, and the one remaining blocker

**Working (active from genesis):**

1. **Block-carried propose/vote applies.** `apply_gov_ops` runs on every block
   (`GOV_OPS_ACTIVATION_HEIGHT = 0`, `governance.rs:151`). It is authoritative: it
   re-derives every verdict from block bytes alone (`tx.from` is the proposer/voter,
   `height_observed == block.height`, `proposal_id == next_id` for proposes, block
   timestamp as the clock), in tx/payload order. The SVM arms only charge gas and push
   (pure carriers); a refused op costs its reporter gas and never fails the block.
2. **Deterministic finalize + execute exists.** `apply_governance_transition`
   (`state_engine/apply.rs`) finalizes every `Open` proposal whose voting window closed
   and executes every `Passed`, matured `GovAction` in ascending id order, with the tally
   re-derived from committed state. It takes no write lock on an ordinary block. All 13
   `GovAction` types go through this sweep; `SoftwareUpgrade`/`CancelUpgrade` are filtered
   out unless `upgrade_exec_active_at(height)` is also true.
3. **The plan is committed.** `commitment.rs` hashes `applied.upgrade_plan` (presence,
   name, height, sha256), so a local-only plan can no longer hide behind an identical
   root.
4. **The RPC write path is a block-form front end.** `stell_submitProposal` /
   `stell_vote` accept a signed `tx` carrying `SysCallGovPropose` / `SysCallGovVote` and
   only admit it to the mempool. The legacy direct-parameter form stays solo-only and
   refuses on `validator_set.len() > 1`; the escape hatch
   `STELL_GOV_ALLOW_MULTINODE_WRITES=1` is still documented as fork-prone.

**Remaining blocker:** `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX`
(`governance.rs:80`). A passed `SoftwareUpgrade`/`CancelUpgrade` is finalized but never
matures into `upgrade_plan`, so the binary halt/exec path stays unreachable. This gate is
deliberately separate from `GOV_OPS_ACTIVATION_HEIGHT`: a binary rollout is a heavier,
separately ratified decision than a parameter change.

#### 1.2.3 The halt is a predicate, not a one-shot event

The shipped predicate is `plan.height <= height` (`node/consensus_driver.rs:3129`), so a
node that was offline at `H`, restarts, or snapshot-syncs to `H` or beyond still refuses
to keep running the old rules. The plan is committed (`commitment.rs:784`), the pre-halt
persistence queue is drained, and a durable marker plus startup guard refuses consensus
until the upgraded binary proves the plan (`node/upgrade_halt.rs:338-407`,
`node/bootstrap.rs:940-966`). A plan whose `height` is already past at execution time
still halts on the first block that observes it; it is not a silent dud.

#### 1.2.4 Exit 42 and the supervisor

The halt path calls `std::process::exit(42)` **without** the graceful drain that the
SIGTERM handler uses:

- SIGTERM: `request_flush` → `wait_for_persist_drain` → `exit(0)`
  (`node/bootstrap.rs:924-969`; drain helper `storage.rs:3609-3643`).
- Upgrade: `request_flush(); snapshot_state(...); snapshot_domains(...);`
  then `exit(42)` immediately (`node/consensus_driver.rs:2892-2896,2975`). Those three
  calls only **enqueue** jobs (`storage.rs:3389-3450,3501-3530`), so the persistence
  writer may not have written them when the process dies.

The unit files do nothing special for 42: `Restart=always`, `RestartSec=5`,
`StartLimitIntervalSec=300`, `StartLimitBurst=5`
(`stellereum/scripts/systemd/stell-nodeA.service:23-32`). `rg -n "\b42\b" scripts/systemd
stellereum/scripts/systemd ops scripts/cluster-watchdog.sh` → **no hits**. The watchdog
polls every 60 s (`scripts/cluster-watchdog.sh:55`) and only knows "down/crash-looping"
(`:230-262`); it cannot distinguish "halted for upgrade" from a crash.

So the supervisor contract today is implicit: *restart the same command line*. Unless the
operator atomically replaced the binary at the unit's `ExecStart` path before `H`
(`docs/OPERATIONS.md:1578-1587`), the restart runs the **old** binary.

#### 1.2.5 In-flight consensus/state at the halt

The exit is **not mid-block**: it happens at the end of the finalize lane for height `H`,
after the block was applied and after `enqueue_block`, `enqueue_finalized`,
`enqueue_consensus` (`node/consensus_driver.rs:2858-2878`). Consensus safety survives:
the checkpoint is written before the upgrade check, restoring the lock and capping the
round at 64 (`node/consensus_driver.rs:638-680`). What is *not* guaranteed is durability:
the practical RPO of `exit(42)` is "whatever is still in the queue", bounded by
`PERSIST_QUEUE_CAP = 8192` jobs (`storage.rs:2985`) and the 25-height flush barrier
(`node/consensus_driver.rs:2866-2870`). On restart the node heals from the last paired
snapshot (`node/consensus_driver.rs:559-630`), so the loss is time, not safety.

**UNVERIFIED (needs a live rehearsal):** with `STELL_AUTO_UPGRADE=1`, `execve` replaces the
image while the sled handles (`Storage::db`, opened in `storage.rs:421-455`) are still open.
sled's on-disk lock may survive `execve`; if it does, the new image can fail to open the
same store. The staging rules prove *which bytes run*, not that the storage lock is
released. Test this on a throwaway cluster before ever arming live migration.

### 1.3 Identity-breaking upgrades

Three separate identities, only one of which is committed to consensus:

| Identity | Derivation | Where pinned | Changing it breaks |
|---|---|---|---|
| Consensus `ValidatorId` | **Ed25519 public key** (`consensus/types.rs:16`; `Vote::sign` uses `key.verifying_key().to_bytes()`, `:1017`; `sign_with_falcon`, `:1181-1183`) | Config `validators:` list of `blake3(ed_pub)[..20]` (`node/bootstrap.rs:694-698`) | Genesis root (validator funding, `node/bootstrap.rs:719`), proposer schedules, all historical QCs |
| Vote authority | Falcon-512 key **registered against** the Ed `ValidatorId`, resolved *at the vote's height* (`consensus/types.rs:1095-1107`; `consensus/rotation.rs:64-83`) | In-memory registry seeded from the node's `falcon.key` and from `STELL_PEER_PQ_KEYS` (`node/consensus_driver.rs:115-158`) | A rotated Falcon key that peers do not know makes every vote invalid → downtime jail |
| Transport identity | `pq_id = blake3("infnode-pqid-v1"‖falcon_pk)[..20]` (`infnode/.../proto.rs:489-499`) | Each peer's `pq-pub` (897-byte Falcon key) in `node.yaml`; mandatory (`infnode/.../config.rs:60-66,132-136`) | A new `pq-identity.key` requires editing every peer's config; otherwise the peer refuses the pin (`node.rs:4143-4160`) |

The PQ-only wipe is a **flag day, not a window**: the transport frame version is exactly
`2`, and v1 (classical Ed25519 trailer) is refused with no fallback
(`infnode/.../proto.rs:133-137,264-267`). The handshake likewise has no classical mode:
`pq_mixed_policy` refuses an absent offer, a missing local identity, a bad suite/version or
a bad tag at **every** height (`proto.rs:421-441`). This contradicts the older "mixed-net
window" plan in `docs/CLASSICAL_REMOVAL_PHASE23.md:123-127`; the code is ahead of the doc.

Keys are auto-generated when absent: `NodeKeyBundle::load_or_generate`
(`node/bootstrap.rs:552-560`), `load_or_generate_consensus_key` generates a fresh Ed key
(`node_keys.rs:645-675`), `load_or_generate_node_keys` generates a fresh KEM key
(`:747-755`). A wiped `keys/` silently becomes a new identity. For validators this fails
closed: a new Ed key changes the validator set, hence the genesis root, and startup refuses
with `genesis state root mismatch` (`node/bootstrap.rs:885-899`).

#### 1.3.1 What a mixed-version cluster actually does

| Change class | Old↔new behaviour | Fork or fail-closed? |
|---|---|---|
| `FRAME_VERSION` / handshake | Every frame rejected (`proto.rs:266`); no peer connectivity | **Fail-closed isolation** (no traffic, no fork) |
| Appended `ConsensusMsg` variant | Old binary fails exact-length decode with trailing bytes (`consensus_net.rs:539-556`) and drops the message. Appending is explicitly decode-safe for *readers that know it* (`:303-315`) | **Liveness loss** for the old node; no fork |
| Existing variant field change | Old decode fails → message dropped | Liveness loss |
| Height-gated state change (emission, gov ops) | New nodes compute a different post-`H` root; old proposals are rejected at the root check | **Stall**, not fork (quorum 3-of-4 can proceed without one straggler; two stragglers halt) |
| Sortition change (QC split, CN-VRF, beacon) | Mismatched proposer/committee → `"wrong proposer"` rejections (`runtime/consensus_step.rs:693,1143,1160`; `consensus/engine.rs:1296`) | **Stall**, not fork |
| `ValidatorId` derivation change | Different genesis root and different vote preimages | **Different chain** (genesis reset required) |
| `COMMITMENT_VERSION` bump | Different state root for the *same* state; old snapshots cannot verify | **Genesis reset required** (`commitment.rs:93-98`) |
| Validator set / faucet / chain id change | Different genesis root (`node/bootstrap.rs:885-899`) or different block hashes (`sharding/block.rs:818-825`) | **Different chain** / no traffic |
| Rotated Falcon consensus key without peer registry update | New votes fail `Vote::verify` (`consensus/types.rs:1095-1107`) | Old node effectively silent; **downtime jail** (`staking.rs:258-267`) |

Important: the topic is epoch-scoped by the **genesis state root**
(`network.rs:23-58,43-45`), so two different genesis roots cannot even hear each other.
A validator-set change is therefore a hard partition, not a fork of one chain.

#### 1.3.2 In-place upgrade vs genesis reset — the exact preconditions

**In-place (same chain, swap the binary) requires *all* of these to stay identical:**

1. **Genesis inputs:** the consensus validator set (Ed-key-derived ids), the faucet seed,
   the `GENESIS_*` balances/bonds, and `COMMITMENT_VERSION`
   (`node/bootstrap.rs:885-899`; `commitment.rs:93-100`). The first three determine the
   genesis accounts; `COMMITMENT_VERSION` is mixed into the digest
   (`commitment.rs:1686`).
2. **Wire identity:** `FRAME_VERSION` and the handshake suite/transcript version
   (`infnode/.../proto.rs:137,319-321`). All nodes must switch together.
3. **Signature domains:** the block domain `STELLEREUM_BLOCK_V3` (`sharding/block.rs:821`)
   and the vote domain `STELLEREUM_BFT_VOTE_V2` (`consensus/types.rs:991`). Changing either
   invalidates all historical hashes/signatures.
4. **Snapshot readability:** the new binary must read every old shape it may encounter
   (the V1..V7 fallback chain, `storage.rs:2600-2700`); old binaries need not read new
   shapes.
5. **Identity plumbing:** `ValidatorId` derivation
   (`consensus/types.rs:16,1095-1107`) and the staking/env PQ key binding
   (`consensus/rotation.rs:64-83`; `node/consensus_driver.rs:115-158`). Rotating a key is
   in-place only if every peer learns it in the same window.
6. **Chain id:** `STELL_CHAIN_ID` enters every block hash and vote preimage
   (`sharding/block.rs:824`; `consensus/types.rs:992`). Changing it is a new network.

**A genesis reset is required as soon as any of 1, 3, 5 (derivation) or 6 changes.** It is
*not* required for a pure height-gate flip, a wire-only swap, or a key rotation that peers
learn in time. A `COMMITMENT_VERSION` bump always implies a genesis reset, but a genesis
reset does not require a version bump.

Procedure for a reset (all nodes): stop every unit; archive `data/` and `keys/` off-host;
set a new `STELL_CHAIN_ID`; wipe `./data` on **all** nodes (never one file, and never
`keys/` unless the identity is deliberately being replaced); derive and publish the new
genesis root + first checkpoint out of band; start all; require identical
`stell_getStateRoot` before declaring the chain live. If the reset changes the genesis state
root (validator set, faucet, `GENESIS_*`, `COMMITMENT_VERSION`), the epoch/topic changes
automatically (`network.rs:23-58`), so old-chain traffic cannot leak in. A
**chain-id-only** reset keeps the same epoch/topic (the id is not in the state root) and
relies on block-hash and vote-preimage separation instead
(`sharding/block.rs:824`; `consensus/types.rs:992`).

### 1.4 State compatibility

- **`COMMITMENT_VERSION = 5`** (`commitment.rs:100`) is mixed into the digest
  (`commitment.rs:1686`). The doc comment is explicit: a bump means "every data directory
  needs a wipe" (`:93-98`). A new binary with a higher version cannot verify an old
  snapshot: the header at `S+1` commits to the old root and the throwaway restore fails
  (`storage.rs:1468-1513`).
- **Freeze rule on `DomainSnapshot`/`BlockHeaderRecord`:** "NEVER add fields to this
  struct … New committed domains get their OWN tree + snapshot/restore pair … If this rule
  must ever break, ship a versioned upgrade wrapper … in the SAME commit"
  (`storage.rs:113-121`). `BlockHeaderRecord` is the on-disk header row
  (`storage.rs:127-152`) and is read directly from the wire too (`network.rs:1040-1055`).
- **Versioned domain shapes:** `DomainSnapshotV1..V7` are read-only legacy shapes
  (`storage.rs:2188-2400`), with `StakingLedgerV4` (`:2308-2369`) and the macro-generated
  `V4..V6` (`:2588-2590`). The lenient decoder tries current → legacy contracts →
  V7 → V3 → V2 → V1, each with a loud migration warning
  (`storage.rs:2600-2700`). The **trust-anchor** path is strict: only the current shape,
  exact length, no fallback (`storage.rs:2687-2720`, `decode_domain_snapshot_strict`).
- **Bridge:** `BridgeStateV1` upgrades pre-rate-limit snapshots with zeroed new counters,
  with an explicit "verify real minted supply out-of-band" warning (`bridge.rs:1160-1205`).
- **Accounts:** `StateSnapshotV2` = accounts + penalty map + `total_minted_nano`, with an
  EOF-tolerant trailing field (`state_engine/types.rs:645-698`). Legacy bare
  `Vec<AccountState>` is still accepted (`:638-640`).
- **Snapshot container:** local store `state`/`domains`/`session_keys`/`bridge`/`zkml`/
  `cross_shard`/`cnvrf_v3`/`pq_keys` (`storage.rs:24-110`; sync bundle
  `sync.rs:977-985`). Network publication is chunked: 1 MiB chunks, 20 s per-chunk
  timeout, 6 retries, 300 s per-blob budget, 2 concurrent large blobs
  (`sync.rs:1488-1515,1660-1700`). Pointer publication is fail-closed: it advances only if
  the blob landed (`network.rs:1128-1175`).
- **Retention:** archive mode is the default and never prunes (`storage.rs:250-288,1576-1595`);
  prune mode keeps `STELL_KEEP_BLOCKS` bodies (default 50 000) and `snap_int * 3` snapshots
  (`node/consensus_driver.rs:3310-3318`). DHT bodies/headers keep 8 000 heights
  (`network.rs:183`), DHT snapshots keep a "forever" TTL (`network.rs:233-239,1135`).

#### 1.4.1 What force-wipes a data directory

| Trigger | Code | Message / action |
|---|---|---|
| Genesis inputs changed | `node/bootstrap.rs:885-899`; message `bootstrap.rs:330-342` | `genesis state root mismatch … Wipe ./data …` |
| `COMMITMENT_VERSION` bump | `commitment.rs:93-98` | Same mismatch (new root) |
| Snapshots exist but no state/domain pair at one height | `storage.rs:2844-2852` | `refusing to resume on half a snapshot` |
| Restored root mismatch or no anchor below the tip | `storage.rs:1481-1512` | `wipe the data directory or restore a verified backup` |
| Cannot load/verify the paired snapshot at boot | `node/consensus_driver.rs:457-466` | `REFUSING to run on unverified state` → `exit(1)` |
| Cannot heal `S → F` after 3 attempts | `node/consensus_driver.rs:559-630`; `HEAL_MAX_ATTEMPTS = 3` at `node/policy.rs:890` | `REFUSING to join consensus on unhealed state` → `exit(1)` |
| Store unreadable / corrupt sled | `storage.rs:421-455` (open), no recovery path | Startup error; restore a backup |

Legacy snapshot shapes do **not** force a wipe — they are upgraded on read. A snapshot
written by a *newer* binary is undecodable by an older one (there is no forward-compatible
decoder), which is exactly the rollback trap in §1.7.

### 1.5 Disaster-recovery machinery

- **Publish:** on the finalize path, every `snap_int` heights (default 1000) the node
  captures accounts + domains + aux, writes them locally and publishes
  state/domains/headers to the DHT (`node/consensus_driver.rs:3010-3080,3230-3280`).
  `try_snapshot_sync` first follows the `latest-snapshot` pointer, then probes the `%100`
  grid downward at most 8 steps (`node/sync.rs:82-107`), accepting only a snapshot whose
  successor header is QC-proven against the set at that height
  (`node/sync.rs:96-330`; `sync.rs:579-680`).
- **Restore:** `fast_sync_state` restores into a **throwaway** engine, installs every
  domain blob, and requires the exact expected root before mutating live state
  (`sync.rs:1120-1200`). On boot, the local path is the same two-phase pattern
  (`storage.rs:2824-2960`).
- **Heal:** `heal_engine_to_head` walks backward from the finalized head collecting hashes
  (local bodies first, then peers), then replays `S+1..F` requiring a verifiable precommit
  QC and the running engine root per block (`node/consensus_driver.rs:710-820`). Failure
  after 3 attempts refuses to join (`:604-630`).
- **Dirty-dir / fresh-join guards:** a fresh data dir with peers configured refuses unless
  `STELL_OBSERVER=1` or `STELL_NEW_CHAIN=1`
  (`node/bootstrap.rs:660-690`; `bootstrap.rs:130-190`). The preflight used by
  `node-bootstrap` additionally requires observer, faucet key, clean dir, peer pointer and
  a non-empty validator set (`bootstrap.rs:79-95`; `cli/handlers.rs:1371-1410`).
- **Backups:** two non-equivalent systems:
  - `scripts/backup_verify.sh` + `scripts/backup_offhost.sh` +
    `scripts/backup_restore_drill.sh` — 3-2-1, encrypted, manifest-checked, with a
    boot-read check. **Keys are inventory-only, never copied**
    (`ops/backup_runbook.md:9-30,72-88`; `:24`).
  - `stellereum/scripts/backup/backup.sh` + `restore.sh` — tarball includes
    `node.yaml`, `data/` and **`keys/`** (`stellereum/scripts/backup/backup.sh:12-22`);
    `restore.sh` refuses if a live process holds the sled lock, snapshots current state to
    `pre-restore-<node>-<ts>.tar.gz`, then does not start the node
    (`stellereum/scripts/backup/restore.sh:11-16,79-109,126`).
    The two policies contradict each other: a host-loss recovery **needs** `keys/`, because
    a lost `validator.key` is unrecoverable identity (`node_keys.rs:716-719`).
- **Drills:** `ops/upgrade_rehearsal.md` is a concrete binary-swap rehearsal (baseline →
  snapshot → swap → catch-up checks → rollback → roll-forward) with explicit pass criteria
  (`:20-136`). `ops/backup_runbook.md:72-88` defines a quarterly restore drill. Neither has
  evidence of having been run on the live 4-node set in this tree
  (**UNVERIFIED**; `ops/LOCAL_VALIDATION.md` is a local-cluster record only).

### 1.6 Actual recovery time for a 4-node cluster

Quorum is `floor(2n/3)+1` (`consensus/sortition.rs:24-29`); each validator is added with
power 1 (`node/bootstrap.rs:424-430`). For n=4: **quorum = 3**, so one node down is
survivable, two down halts finality.

Components (code-derived):

| Phase | Bound | Source |
|---|---|---|
| Detection (metrics) | `delta(height[10m]) <= 0` for 5 m | `ops/alerts.md:17` |
| Detection (watchdog) | 60 s poll | `scripts/cluster-watchdog.sh:55` |
| Startup + local snapshot verify | seconds for a small state; one extra full restore | `storage.rs:2824-2960` |
| Snapshot fetch | ≤ 300 s per blob attempt; manifest 10 s; 20 s/chunk ×6 | `sync.rs:1488-1515` |
| Body walk | ≤ 256 blocks, ~100–300 ms/fetch in the code's own estimate → 25–77 s | `node/sync.rs:685-700` |
| Heal retries | 3 × 1 s | `node/policy.rs:890`; `node/consensus_driver.rs:626` |
| Round-trip through catch-up tick | event-driven; 30 s backstop (`STELL_CATCHUP_INTERVAL_MS`), skipped at tip; reactive floor 500 ms | `node/policy.rs` (`CATCHUP_INTERVAL_DEFAULT_MS`, `REACTIVE_CATCHUP_MIN_GAP_MS`, `catchup_action`) |

**Measured datapoint (local testnet, not mainnet):** `multinode/nodeB` had a 101 MB store
and a **411-byte** state snapshot at height 750, with `STELL_SNAPSHOT_INTERVAL=500`,
`STELL_ARCHIVE=0`, `STELL_KEEP_BLOCKS=8000`, tip 767
(`rg -o "publishing [0-9]+ bytes as …" multinode/nodeB/live.log | tail`;
`rg -n "SNAPSHOT_INTERVAL|ARCHIVE|KEEP_BLOCKS" multinode/nodeB/env.B`). Restore cost there is
dominated by headers/bodies, not bytes. Mainnet-scale snapshot size is **UNVERIFIED**
(no live data dir was read).

**The hard case — the 256/1100 gap.** After a snapshot restore at `B`, the node sets its
finalized head to `B` and refuses a walk when `peer_height - B > 256`
(`node/sync.rs:328,698`). Consecutive snapshots can be `snap_int + CATCHUP_GRID = 1100`
apart (`snapshot_cadence.rs:29,79-82`; default 1000 at `node/policy.rs:246-252`). Therefore:

- **Live chain, one node lost state:** worst case the node idles until the next snapshot
  (≤ ~1100 heights), then catches up. At 50 ms/block that is ≤ 55 s; at 500 ms/block
  ≤ 9 min. Typical: 1–5 min.
- **Halted chain (two of four lost state):** the two survivors cannot finalize (2 < 3), the
  tip freezes, **no further snapshot is produced**, and if `H - B > 256` the first
  recovering node can never close the gap. Probability under uniform halt timing ≈
  `(1100-256)/1100 ≈ 77 %`. Recovery then requires a filesystem backup of a data dir or a
  manual copy from a survivor — not snapshot-sync. **This is the single most important DR
  finding.**
- **Two nodes lost, gap ≤ 256:** chain outage ≈ time to recover **one** node (the second is
  off the critical path): ~1–10 min WAN, plus detection.

RPO:

| Loss | RPO | Why |
|---|---|---|
| Node process killed | ≤ 25 heights of bodies/finality (flush barrier), plus whatever the queue held | `node/consensus_driver.rs:2866-2870`; `PERSIST_QUEUE_CAP=8192` |
| Node `exit(42)` (upgrade) | Same, but the flush is **not awaited** | §1.2.4 |
| Node data dir wiped | 0 consensus state (re-derived from peers); local receipts and mempool are lost — neither is consensus state | `storage.rs:2824-2960` restores no receipts; mempool is a separate file (`node/bootstrap.rs:1183`) |
| Total host loss | 0 if `keys/` is backed up; **identity loss** if not | `node_keys.rs:716-719`; `ops/backup_runbook.md:24` |

A mitigation already available with **no code change**: set `STELL_SNAPSHOT_INTERVAL ≤ 156`
on every node (minimum 50, `node/policy.rs:246-252`). Then
`worst_case_gap = interval + 100 ≤ 256`, so the body walk can always close the gap, including
on a halted chain. `200` is *not* enough for the guarantee (gap ≤ 300 > 256); it only
shortens the wait to the next snapshot. Snapshot cadence is node-local, not consensus.

### 1.7 Rollback

- **Before the halt height `H` (and before any state-affecting gate activates):** safe.
  The old binary reads the same state (same `COMMITMENT_VERSION`, same snapshot shapes) and
  derives the same genesis root. `ops/upgrade_rehearsal.md:112-129` gives the exact
  stop → restore data dir → restore binary → start procedure, and
  `docs/OPERATIONS.md:1578-1625` gives the atomic deploy + backup pin. Rollback triggers
  are listed at `ops/upgrade_rehearsal.md:113-117`.
- **After `H` (a state-affecting gate is live):** **not supported.** Rolling back one binary
  means the old binary computes a different post-`H` root. It cannot validate new blocks;
  new nodes reject its proposals. Restoring a pre-`H` data dir is worse: the node sits at
  `H' < H` while the network is past `H`, and finalized blocks cannot be rewound (locks are
  restored at `node/consensus_driver.rs:638-680`). The only "rollback" after `H` is a
  coordinated **new genesis** with a wiped `./data` on every node.
- **Wire/identity-only upgrade (no state gate):** rolling back one version after the swap
  isolates the node (frame version exact-match) but does not corrupt state; with quorum
  3-of-4 the chain continues. There is no way to run "half v1, half v2" peers.
- **A `COMMITMENT_VERSION` bump** closes the rollback window *at genesis*: old snapshots
  cannot be read at all, so the pre-upgrade backup is the only object that can be rolled
  back to — and only as a new chain.

---

## 2. Minimal design proposal for safe upgrades

Design rule: reuse what is already in the tree; do not invent a parallel mechanism. The
single most important change is **making the on-chain path work** — today the safe answer is
"there is no on-chain path", and that is an operational risk, not a feature.

### 2.1 Principles

1. **Consensus gates are compile-time constants, height predicates, and committed state.**
   No env for anything that changes validity (retire
   `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`; `chain_binding.rs:33,66-78`).
2. **The halt condition is `height >= H`, not `height == H`.** A node that missed the event
   must still refuse to run the wrong rules.
3. **The upgrade plan is committed** (part of the state root) and its execution is
   **deterministic** (block-carried), so every node derives the same plan from the same
   blocks.
4. **Binary identity is verifiable** (the running executable's SHA-256), and a node that
   cannot prove it is the binary the plan named **must not vote**.
5. **Checkpoint before halt** and **drain before exit**; the pre-upgrade snapshot is the
   rollback anchor.
6. **The rollback window closes at `H`** and the proposal must say so out loud.

### 2.2 Components, each mapped onto an existing mechanism

#### C1. Protocol version + negotiation (reuse `chain_spec`, vote domain)

- Add `pub const PROTOCOL_VERSION: u16` and
  `pub const PROTOCOL_VERSION_ACTIVATION_HEIGHT: u64` to `chain_spec.rs` (same shape as
  every other gate; `chain_spec.rs:50-110,117-176`).
- At/after the activation height, extend the **vote preimage** from
  `STELLEREUM_BFT_VOTE_V2` to a versioned domain that includes `PROTOCOL_VERSION`
  (`consensus/types.rs:984-1005`). Pre-activation bytes stay byte-identical (the same
  conditional pattern used by every non-empty commitment in `sharding/block.rs:849-877`).
  Cross-version votes then fail verification on both sides → **clean fail-closed halt, no
  fork, no state-root change**.
- Add an **appended** `ConsensusMsg::Hello { protocol_version, schedule_hash, exe_sha256 }`
  variant. Appending is explicitly decode-safe (`consensus_net.rs:303-315`); old binaries
  drop it (loud on the new side only). This is the observability half: operators can see
  "peer 3 is on protocol 4" instead of guessing from stalls.
- Compute `schedule_hash = blake3(chain_spec::summary_lines())`. This single value covers
  every gate, including the six the registry currently omits
  (`MEV_RESHARE`, `GOV_OPS`, `UPGRADE_EXEC`, `SPRT_TIER3`, `CHAIN_BINDING`,
  `ZKML_CONTEXT_BINDING`).

#### C2. Announced upgrade height (reuse `GovAction::SoftwareUpgrade`)

- Keep `SoftwareUpgrade { name, height, sha256 }` (`governance.rs:207-213`); it already
  carries the binary digest and is committed as a *pending proposal*
  (`commitment.rs:668-671`).
- **Fix validation:** reject a plan unless its `height` is at least `MIN_UPGRADE_DELAY`
  heights beyond the execution height. Express the delay as a **wall-clock lead time
  converted at the live cadence** (e.g. 2 days ≈ 3.46 M heights at 50 ms) rather than reusing
  `GOV_TIMELOCK_HEIGHTS`, which is only ~6 minutes at the live floor. A past height still
  halts deterministically on the first block that sees it (`plan.height <= height`,
  `node/consensus_driver.rs:3129`).
- ~~**Commit the executed plan**~~ **DONE:** `commitment.rs:784` hashes
  `applied.upgrade_plan` (presence/name/height/sha256). No `COMMITMENT_VERSION` bump was
  needed because the arm is self-conditional (`None` contributes nothing).
- ~~**Make execution deterministic**~~ **DONE:** `apply_governance_transition` finalizes and
  executes every due action in ascending id order with `now = block.timestamp` and
  `cur_height = block.height`. The only remaining piece is the separate
  `UPGRADE_EXEC_ACTIVATION_HEIGHT` gate for `SoftwareUpgrade`/`CancelUpgrade`.
- ~~**Make propose/vote block-carried**~~ **DONE:** `GOV_OPS_ACTIVATION_HEIGHT = 0`, and
  the RPC `tx` form admits signed `SysCallGovPropose`/`SysCallGovVote` payloads on every
  node.

#### C3. Binary hash pinning

- Add `stellereum/build.rs` that sets `STELL_BUILD_HASH` (git SHA) and
  `STELL_BUILD_DIRTY`; today `metrics.rs:1274-1295` documents a build script that does not
  exist, so `/api/version` reports `"unknown"` for the hash
  (`metrics.rs:1288-1293,1353-1360`).
- At startup compute **SHA-256 of `/proc/self/exe`** and expose it as `exe_sha256` in
  `build_info_json()` (`metrics.rs:1353-1360`) and `/api/version`
  (`explorer.rs:2091-2104`). This is the value the plan's `sha256` must match.
- Add a **binary/plan guard** at boot and on every finalize:
  - if `finalized >= plan.height` **and** `exe_sha256 != plan.sha256`, then
    **do not vote** (run as observer) and emit one loud line naming both hashes and the
    plan. This is the fail-closed answer to the "silent straggler" in §1.2.3.
  - a grace window (`plan.height + PROTOCOL_GRACE_HEIGHTS`) after which the check becomes a
    warning instead of a vote refusal, so a later legitimate binary is not blocked by a
    stale plan.
- Keep the existing staged-binary rules unchanged (`governance.rs:751-830`). They are good.

#### C4. Coordinated halt + scheduled restart

- Keep the finalize trigger as `height == plan.height` — that is the intended halt block —
  but add a **state predicate** evaluated at boot and after every sync:
  `finalized >= plan.height` → verify the binary (C3); `finalized < plan.height` → normal
  operation. This makes the halt immune to a missed event: a node that snapshot-syncs past
  `H`, or restarts after it, still refuses to run the wrong rules. A node that is already
  past `H` on the correct binary continues normally.
- Before `exit(42)`, **await** the existing drain helper:
  `request_flush` + `wait_for_persist_drain(|| ap.pending())` (already used by the SIGTERM
  path, `node/bootstrap.rs:960-969`; helper `storage.rs:3609-3643`), then write and fsync a
  checkpoint marker (C5). Budget: the helper caps at 240 s + settle, inside systemd's 300 s
  (`storage.rs:3544-3553`).
- Supervisor contract (document it and encode it in the unit): `Restart=always`,
  `RestartSec=5`, `StartLimitBurst=5` (existing, `stell-nodeA.service:23-32`) **plus**
  `ExecStartPre=/usr/local/bin/stell-upgrade-guard --data-dir .` — a tiny script that reads
  the checkpoint marker (C5) and verifies the `ExecStart` binary's SHA-256 against
  `plan.sha256`, exiting non-zero with a named cause if they differ. This is the piece the
  supervisor is *expected* to do today and does not (`rg -n "\b42\b" scripts/systemd …` →
  no hits).
- Keep `STELL_AUTO_UPGRADE` default OFF (`governance.rs:676-706`) and keep it a
  node-local decision. Do **not** make it "smarter".

#### C5. Migration checkpoints

- Replace the fire-and-forget snapshot in the trigger (`consensus_driver.rs:2892-2896`)
  with an **awaited checkpoint**: capture state + all domains (`storage.rs:3389-3450`), wait
  for the writer to drain, then write a marker record:
  `{height, plan_name, plan_sha256, old_exe_sha256, protocol_version, timestamp}`.
  Reuse the `meta` tree (`storage.rs:56,885-899`) and `BlockHeaderRecord`'s pattern
  (`storage.rs:127-152`) — a small struct, not a `DomainSnapshot` field (freeze rule,
  `storage.rs:113-121`).
- Publish the same marker to peers as a new `ConsensusMsg::UpgradeCheckpoint` (appended),
  so a node that lost its data dir can ask "what was the last upgrade height?" and refuse to
  join a chain whose protocol version it does not speak.
- The checkpoint is the rollback anchor: the runbook refuses to roll back without it.

#### C6. Rollback window

- Define it explicitly: `[plan.height - MIN_UPGRADE_DELAY, plan.height)`.
  `CancelUpgrade` already exists and clears the plan (`governance.rs:1831-1833`); with C2
  it is executable deterministically.
- At `plan.height` the window **closes**. Document it in the proposal text and in the
  marker. After `H`, only forward-fix or a new genesis (matching §1.7).
- Keep the pre-upgrade filesystem backup from `stellereum/scripts/backup/backup.sh`
  (includes `keys/`, `stellereum/scripts/backup/backup.sh:12-22`) and the rehearsal's
  restore step (`ops/upgrade_rehearsal.md:44-60,120-129`). The off-host runbook's
  inventory-only key policy (`ops/backup_runbook.md:24`) is **not sufficient** for host
  loss; add an encrypted keys archive under the same 3-2-1 policy.

#### C7. Snapshot cadence vs the 256-block walk cap

- Two options, both minimal:
  - **Operational (no code):** set `STELL_SNAPSHOT_INTERVAL=200` (or ≤ 156 to make
    `snap_int + 100 ≤ 256`) on every node; it is node-local
    (`node/policy.rs:246-252`).
  - **Code (preferred):** make the walk cap derive from the retention/cadence rather than
    a hard 256, or allow a trusted post-snapshot continuation to walk up to
    `snap_int + CATCHUP_GRID` with the same per-block QC verification
    (`node/sync.rs:685-700`). Do not remove the cap for arbitrary peers.
- Also fix the comments that say "one snapshot per 100 heights"
  (`network.rs:1135`, `node/sync.rs:407,596`) — they contradict the 1000 default and mislead
  operators sizing retention.

#### C8. Registry completeness

- Add `MEV_RESHARE`, `GOV_OPS`, `UPGRADE_EXEC`, `SPRT_TIER3`, `CHAIN_BINDING` and
  `ZKML_CONTEXT_BINDING` to `chain_spec::current_activation_schedule`
  (`chain_spec.rs:130-180`) and expose it (plus `schedule_hash`) over `stell_chainSpec` /
  `/api/version`. Today the only way to read the schedule is a Rust library call; operators
  cannot ask a running binary which rules it will apply, and in particular cannot see the
  `UPGRADE_EXEC` gate that still blocks binary execution.

### 2.3 Operator timeline under the proposal

| T | Action | Mechanism |
|---|---|---|
| T−7 d | Build; `sha256sum` the binary; stage it at `data/upgrades/<name>/stellereum` on every node; confirm `/api/version.exe_sha256` and `schedule_hash` are identical on all four | `governance.rs:726-736`; C3 |
| T−7 d | Open `software_upgrade` with `height = H_future`, `sha256 = <digest>` (block-carried) | C2 |
| T−7 d … T−4 d | 3-day vote; quorum 6 666 bps (`governance.rs:30`) | existing |
| T−2 d | Passed → 7 200-height timelock. At the live 50 ms floor that is ~6 min, so the **plan's own `height`** (not the timelock) is the real lead time; set it days out | `governance.rs:48-60` |
| T−1 h | Pre-upgrade backup (data + keys), rehearse restore on a throwaway node | `stellereum/scripts/backup/backup.sh`; `ops/upgrade_rehearsal.md:44-60` |
| H−1 | Verify every node's `exe_sha256` still equals the *old* build and the staged candidate equals the plan digest | C3 |
| H | All nodes checkpoint (C5) and exit 42 after drain | C4 |
| H | Supervisor restarts; `ExecStartPre` guard selects/validates the new binary | C4 |
| H+1 | Nodes with the new binary vote under `PROTOCOL_VERSION`; a node with the old binary refuses to vote | C1/C3 |
| H+1 … H+1 000 | Verify roots, height, `fork_total`, `weak_qc_refused_total` are flat; keep the pre-upgrade backup until the rollback window is formally closed | `ops/upgrade_rehearsal.md:100-117` |

### 2.4 Mixed-version behaviour under the proposal

| Situation | Result |
|---|---|
| 4/4 new binary | Normal operation at `H+1` |
| 3/4 new, 1 old | The old node's votes fail `PROTOCOL_VERSION` verification; 3 nodes = quorum, chain continues; old node logs "wrong protocol version" and is downtime-jailed (`staking.rs:258-267`) |
| 2/2 split | Both sides below quorum; clean halt. No fork: state roots are identical up to `H`, and the vote domain prevents cross-version finality |
| Old node restarts after `H` | C3 refuses to let it vote; it can serve reads/sync as an observer until upgraded |
| Node missed `H` entirely and snapshot-syncs past it | C3/C4 predicate (`finalized >= plan.height`) still fires; the node refuses to vote on the wrong binary |

### 2.5 Non-goals (deliberately excluded)

- No automatic downgrade. An automatic rollback would re-exec whatever binary is on disk —
  the same class of mistake the staging rules exist to prevent (`docs/OPERATIONS.md:1568-1578`).
- No use of env for consensus gates, including `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`
  (`chain_binding.rs:33`). Retire it into `chain_spec` or delete it.
- No change to quorum, `COMMITMENT_VERSION`, block-commitment domain or `FRAME_VERSION`
  in this proposal. Those are separate, audited flag days (AGENTS.md §7,
  `AGENTS.md:35-37`).

---

## 3. Disaster-recovery runbook (draft)

All commands are for the live layout in `scripts/cluster-nodes.conf` (node A remote,
node B local user unit, C/D remote). Substitute node letters and paths. **Read §1.6 before
choosing a recovery path** — the 256/1100 rule decides whether snapshot-sync can work.

### 3.0 Baseline (do this before any incident)

```bash
# 1) Record identity + build of every node (must be identical on all four).
#    /api/version is served by the GATEWAY, not the JSON-RPC port.
#    Export EXP_A..EXP_D (each node's gateway base, e.g. http://127.0.0.1:8080 for B):
for E in "$EXP_A" "$EXP_B" "$EXP_C" "$EXP_D"; do
  curl -s "$E/api/version" | jq '{version,git_hash,dirty,height,node_id}'
done

# 2) Build the read-only ops tool once (sled-only, a few seconds), then record
#    the genesis root, the finalized tip and the newest state snapshot height:
cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml
stelops doctor /root/nodeA/data/store --text   # finalized tip H, snapshot height B, genesis root

# 3) Full backup WITH keys (host-loss recovery needs them):
systemctl stop stell-nodeA
stellereum/scripts/backup/backup.sh --node A --dir /root/backups --keep 7
systemctl start stell-nodeA
# verify the tarball lists nodeA/keys/ and nodeA/data/:
tar -tzf /root/backups/stell-nodeA-<ts>.tar.gz | head
```

Acceptance: every node reports the same `git_hash`/`exe_sha256`, the same
`stell_chainId`, and `stell_getStateRoot` equal at the same height
(`ops/upgrade_rehearsal.md:20-42`).

### 3.1 Scenario A — one node process dies (disk intact)

- **Detection:** `/readyz` 503 with `no_peers`/`no_finality` (`explorer.rs:1932-1941`);
  watchdog "DOWN" within 60 s (`scripts/cluster-watchdog.sh:55,230-262`); peers' height
  still advances (quorum 3-of-4).
- **Commands:** `systemctl restart stell-node<X>` (or, for B, `systemctl --user restart`).
  Watch `journalctl -u stell-node<X> -f` for `[storage] finalized head at height …` and
  `[storage] healed engine to height …`.
- **Expected:** normally < 60 s; up to ~250 s only when the shutdown drain has a large
  queue (`storage.rs:3544-3553`).
- **RTO:** 1–5 min. **RPO:** ≤ 25 heights of local durability.

### 3.2 Scenario B — one node lost its data dir (keys intact)

- **Detection:** startup refuses or starts at height 0; `journalctl` shows
  `genesis state root mismatch` / `no prior state, starting fresh`.
- **Precondition check (before starting!):** compute the genesis root the node *will*
  derive and compare with a healthy peer's `genesis-root`. If the config or keys changed,
  stop — this is a new chain, not a recovery.
- **Commands (validator with real keys):**
  ```bash
  # stop the unit; keep keys/ untouched
  systemctl stop stell-node<X>
  rm -rf /root/node<X>/data            # only ./data, never keys/
  mkdir -p /root/node<X>/data
  # the fresh-dir guard refuses a validator config with peers unless one of:
  #   STELL_NEW_CHAIN=1  (locally minted genesis MUST be byte-identical to the network's)
  #   STELL_OBSERVER=1   (ONLY if validators: does not list this node)
  # systemd does NOT inherit your shell: put the flag in the unit's EnvironmentFile
  echo 'STELL_NEW_CHAIN=1' >> /root/env.<X>     # or /root/node<X>/env.<X> for B
  systemctl start stell-node<X>
  ```
  Then watch for `[sync] fast-synced state from a snapshot at height B` and
  `[sync] caught up N blocks to height M`; compare `stell_getStateRoot` with a peer.
  If you used `STELL_OBSERVER=1`, remove it after the node has synced and restart to vote
  (`node/bootstrap.rs:396-417` explains the observer trap).
- **Alternative:** restore the pre-incident tarball instead of wiping
  (`stellereum/scripts/backup/restore.sh <tar> <X>`), which preserves receipts and avoids
  the fresh-dir guard. This is preferred when a backup exists.
- **RTO:** 1–10 min if `tip − newest_snapshot ≤ 256`; otherwise **wait for the next
  snapshot** (live chain) or go to §3.3 (halted chain). **RPO:** 0 consensus state;
  local receipts/mempool lost.

### 3.3 Scenario C — two nodes lost state (critical)

- **Detection:** two units down/refusing; the two survivors stop finalizing
  (`delta(stell_consensus_height[10m]) <= 0`, `ops/alerts.md:17`); `stell_consensus_round`
  climbs (`:34`).
- **Immediate decision (5 minutes, before anything else):**
  ```bash
  # On a survivor, read the finalized tip H and the newest state snapshot B:
  stelops doctor /root/nodeA/data/store --text
  curl -s $RPC_A -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' \
       -H 'content-type: application/json'
  ```
  - **If `H − B ≤ 256`:** recover one node via §3.2 while the chain is halted; quorum
    returns as soon as it finalizes, then recover the second.
  - **If `H − B > 256`:** snapshot-sync **cannot** close the gap and the halted chain will
    never publish a newer snapshot. **Do not wipe the remaining data dirs.** Restore one
    node from a filesystem backup (preferred), or copy a survivor's data dir while it is
    stopped:
    ```bash
    systemctl stop stell-nodeA
    rsync -a --delete /root/nodeA/data/ /root/node<X>/data/
    # consensus checkpoint/lock is per-validator: drop the copied lock
    # (the one mutating stelops command; refuses without --force):
    stelops clear-lock /root/node<X>/data/store --force
    systemctl start stell-nodeA
    systemctl start stell-node<X>
    ```
    Copying a peer's data dir is explicitly discouraged as a *join* path
    (`node/bootstrap.rs:1-9`), but it is the only in-tree way out of the stopped-chain
    deadlock. Verify the genesis root and a fresh finalized height before trusting it.
- **RTO:** first node 1–10 min if gap ≤ 256; backup restore 15–60 min otherwise.
- **Chain outage:** equals the time to recover **one** node (quorum needs 3), not two.

### 3.4 Scenario D — a node cannot heal (`REFUSING to join consensus`)

Exact exit paths:
`node/consensus_driver.rs:604-626` (after 3 heal attempts) and `:457-466` (unverified
restore). Decision tree:

1. **Is a pre-incident tarball available?** Restore it (`restore.sh`), start, verify root.
2. **Is a healthy peer within 256 bodies of the node's snapshot?** Wipe `./data`
   (keys kept), boot with `STELL_NEW_CHAIN=1` (validator) or as observer, let snapshot-sync
   run.
3. **Neither?** The node cannot be recovered from the network. Options: copy a peer's data
   dir (stopped) or leave it as an observer and accept it cannot vote. Do **not** wipe other
   nodes to "make it match".

Never delete the store of the last healthy node. `AGENTS.md:31-33` is explicit: no live
store deletion without a human order.

### 3.5 Scenario E — upgrade halt did not converge

- Symptom: nodes exit 42 repeatedly (same height re-triggered because the finalized marker
  was not flushed), or some nodes resumed on the old binary.
- Check: `/api/version.exe_sha256` on each node vs `plan.sha256`; the `[upgrade]` lines in
  `journalctl`.
- Fix: stop the unit, atomically install the correct binary at `ExecStart`
  (`docs/OPERATIONS.md:1578-1587`), start. If the plan is wrong (past height, wrong digest),
  cancel it deterministically (C2 / `CancelUpgrade`, `governance.rs:1831-1833`).
- Never arm `STELL_AUTO_UPGRADE=1` on a single node to "fix" a partial upgrade: it will
  `execve` on that node only and leave the rest behind (`governance.rs:676-706`).

### 3.6 Scenario F — wire/identity mismatch (v1 vs v2 frames, rotated PQ key)

- **Detection:** `unsupported version (classical frame refused)` storm
  (`infnode/.../proto.rs:266`) or every vote from one validator failing verification while
  its process is healthy.
- **Cause:** a different `FRAME_VERSION` build, a different `pq-identity.key` (transport id
  changed), or a rotated `falcon.key` not registered in peers' `STELL_PEER_PQ_KEYS`.
- **Fix:** restore the matching binary/key, or update every peer's `pq-pub` pin /
  `STELL_PEER_PQ_KEYS` in the same window. There is no mixed-mode fallback
  (`proto.rs:421-441`).

### 3.7 Scenario G — rollback

- **Before H:** stop → restore pre-upgrade data dir from the verified snapshot → restore
  the old binary atomically → start → compare roots/height with peers
  (`ops/upgrade_rehearsal.md:120-129`).
- **After H:** do not attempt a one-node rollback. Either forward-fix, or declare a new
  genesis (wipe all `./data`, bump `STELL_CHAIN_ID`, publish a new genesis root). A
  one-node pre-H restore leaves that node unable to validate post-H blocks and is treated
  as downtime.

### 3.8 RTO/RPO summary

| Scenario | RTO | RPO | Self-recoverable? |
|---|---|---|---|
| A: one process dies | 1–5 min | ≤ 25 heights | Yes (systemd) |
| B: one data dir lost, gap ≤ 256 | 1–10 min | 0 consensus | Yes (snapshot-sync) |
| B': one data dir lost, gap > 256, chain live | ≤ next snapshot (≤ 1100 heights; 55 s at 50 ms/block) | 0 consensus | Yes, delayed |
| C: two lost, gap ≤ 256 | 1–10 min (first node) | 0 consensus | Yes |
| C': two lost, gap > 256 (chain halted) | 15–60 min (backup) | 0 consensus | **No** — backup/copy required |
| D: unhealable node | 15–60 min | up to backup age | No |
| E: partial upgrade | 5–30 min | 0 (checkpoint) | No (operator) |
| F: wire/identity mismatch | 5–30 min | 0 | No (operator) |

---

## 4. Code changes required

Risk levels: **L** = local/observability, **M** = operational behaviour, **H** = consensus
or wire.

| # | Change | Owning file(s) | Risk | Why |
|---|---|---|---|---|
| 1 | `PROTOCOL_VERSION` + activation height; version tag in the vote preimage | `consensus/types.rs:984-1005`; `chain_spec.rs` | **H** | Cross-version votes become invalid by construction (C1) |
| 2 | Append `ConsensusMsg::Hello` and `UpgradeCheckpoint` | `consensus_net.rs:290-330` | M | Decode-safe append; observability + post-mortem |
| 3 | `build.rs` + `exe_sha256` in `/api/version` and metrics | `stellereum/build.rs` (new); `metrics.rs:1270-1360`; `explorer.rs:2091-2104` | L | Binary pinning is impossible today (`"unknown"`) |
| 4 | ~~Commit `applied.upgrade_plan`~~ **LANDED** | `commitment.rs:784` | **H** | Plan is now part of the state root |
| 5 | ~~Deterministic `execute_due` sweep for matured proposals~~ **LANDED** (all non-upgrade actions) | `state_engine/apply.rs` (`apply_governance_transition`); `governance.rs::execute_due_governance_at_height` | **H** | Every block executes due actions; `SoftwareUpgrade`/`CancelUpgrade` still need gate #6 |
| 6 | ~~Activate `GOV_OPS_ACTIVATION_HEIGHT`~~ **LANDED at 0**; ratify `UPGRADE_EXEC_ACTIVATION_HEIGHT` to enable binary execution | `governance.rs:80,151`; `state_engine/apply.rs` | **H** | Multi-node governance works; upgrade execution does not until the second gate opens |
| 7 | `plan.height` future-window validation + post-sync `>=` halt predicate | `governance.rs:333-345`; `node/consensus_driver.rs:2885-2897` | M | Event-based halt is missed by offline/restarted nodes |
| 8 | Await persist drain + write an upgrade checkpoint marker before exit 42 | `node/consensus_driver.rs:2892-2975`; `storage.rs:3609-3643` | M | Best-effort flush loses the pre-upgrade checkpoint |
| 9 | Add `MEV_RESHARE`/`GOV_OPS`/`UPGRADE_EXEC`/`SPRT_TIER3`/`CHAIN_BINDING`/`ZKML_CONTEXT_BINDING` to `chain_spec`; expose `stell_chainSpec` + `schedule_hash` | `chain_spec.rs:130-180`; `rpc/*` | L | Operators cannot inspect the binary's rules; the schedule still hides the gate that blocks `SoftwareUpgrade` execution |
| 10 | Raise/derive the body-walk cap relative to snapshot cadence (or document `STELL_SNAPSHOT_INTERVAL ≤ 156`) | `node/sync.rs:685-700`; `snapshot_cadence.rs:79-82` | M | The 256 vs 1100 deadlock (§1.6) |
| 11 | Retire `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` env; move to `chain_spec` | `chain_binding.rs:33-78`; `state_engine/parallel.rs:804`; `node/consensus_driver.rs:1555` | **H** | Only remaining env-driven consensus gate; a rolling edit forks |
| 12 | Fix `docs/OPERATIONS.md` §12 fallback claim | `docs/OPERATIONS.md:1568-1578` | L | Doc says a hash mismatch stops the fallback; code tries the next candidate (`consensus_driver.rs:2930-2965`) |
| 13 | Reconcile backup policies (keys inventory-only vs keys-in-tarball) and document the encrypted-keys path | `ops/backup_runbook.md:24`; `stellereum/scripts/backup/BACKUP.md` | M | Host loss without keys is unrecoverable |
| 14 | Fix stale ops docs: `identity.key` is no longer the node identity (`docs/OPERATIONS.md:1210-1217` vs `node_keys.rs:632-645`); snapshot "per 100 heights" comments (`network.rs:1135`, `node/sync.rs:407,596`) | docs + comments | L | Misleads recovery decisions |

Order of landing: 9 → 3 → 8 → 7 → 10 (all non-consensus) can ship first; 1/2 require a
coordinated flag-day; 4/5/6 are one project (on-chain governance) and must land together,
before the first governed upgrade.

---

## 5. Verification appendix (commands actually run)

```text
$ rg -n "pub const \w*ACTIVATION_HEIGHT\s*:\s*u64\s*=" stellereum/src infnode/crates
(10 lines, pasted in §1.1)

$ rg -n "STELL_AUTO_UPGRADE" -g '!target' -g '!.git' .
stellereum/src/governance.rs:676 / :704 / :711
stellereum/src/node/bootstrap.rs:455 / :473 / :480
stellereum/src/node/consensus_driver.rs:2911
docs/OPERATIONS.md:1405-1805
stellereum/docs/OPERATIONS.md:1405-1805

$ rg -n "process::exit" stellereum/src
consensus_driver.rs:466 (unverified restore), :626 (unhealed), :2975 (exit 42)
node/bootstrap.rs:969 (graceful SIGTERM, exit 0)

$ rg -n "execute_at_height\(|execute_with_oracle" stellereum/src
governance.rs (definition + tests), rpc/writes.rs:678  ← the only live caller

$ rg -n "upgrade_plan" stellereum/src/commitment.rs
(no output)

$ rg -n "\b42\b" scripts/systemd stellereum/scripts/systemd ops scripts/cluster-watchdog.sh
(no output)

$ rg -o "publishing [0-9]+ bytes as [^ ]+" multinode/nodeB/live.log | tail
publishing 411 bytes as 26774a50fe7bdd07_snap_0_750
```

---

## 6. UNVERIFIED items (stated so they are not mistaken for facts)

1. **`execve` + sled lock.** No test or rehearsal in the tree exercises
   `STELL_AUTO_UPGRADE=1` end-to-end; whether the new image can reopen `./data/store` after
   `execve` while the old file descriptors/locks are still live is **UNVERIFIED**. Must be
   rehearsed before arming live.
2. **Mainnet snapshot size.** Only a 411-byte snapshot from the local testnet was measured.
   The tens-of-MB figure is a comment (`sync.rs:1488-1515`), not a measurement here.
3. **Whether the live cluster currently sets `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`,
   `STELL_PURE_PQ`, or `STELL_NEW_CHAIN`.** Only `multinode/nodeB/env.B` was read; remote
   `env.A/C/D` are not in this tree. **UNVERIFIED.**
4. **Whether a live 4-node upgrade has ever been rehearsed.** The rehearsal document and
   the local-cluster harness exist, but no log/record of a real 4-node run is in the tree.
   `docs/TESTNET_READINESS_OPS.md:432-438` still lists "no upgrade/rollback rehearsal" as a
   gap.
5. **The exact wall-clock block cadence on the live chain.** `DEFAULT_MIN_BLOCK_MS = 50`
   (`node/policy.rs:356`), but production env may override it; the ranges in §1.6 scale
   linearly with it.
6. **Whether the third candidate path (`/usr/local/bin/stellereum.new`) is used in
   production.** It is code (`governance.rs:734-736`) but no unit or script stages it.
