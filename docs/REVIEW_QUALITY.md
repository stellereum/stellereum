# Code-quality review — fake code, silent failures, panics, doc drift, gates, coverage, boundaries

**Date:** 2026-11-18. **Tree:** `/home/imm/stellereum-project` (dirty, HEAD `0fdf1eefc`).
**Mode:** read-only. No source/test file was modified. This is the only file written.
**Evidence run:** `cargo clippy --all-targets -- -D warnings` in `stellereum/` → 0 warnings, 0 errors;
same in `infnode/` → 0 warnings, 0 errors. `cargo test --lib` filters
`quorum_formulas_are_pinned_per_domain` and `gated_off_corresponds_strictly_to_u64_max` → both pass
(1338 lib tests total). Full suite deliberately not run.

Severity: **S1** consensus/security, **S2** high, **S3** medium, **S4** cosmetic.
"Blocks" = what the finding blocks: `public` (public testnet), `mainnet` (mainnet only), `no`.
Anything I could not settle from the tree is marked **UNVERIFIED**.

---

## Verdict

**The code is in good shape; the documentation is the defect.** Zero `todo!`/`unimplemented!`/`FIXME`/`XXX`,
zero clippy findings, quorum math centralised, and no input-reachable panic found in consensus/state/RPC.
But: (1) one env var still changes block validity inside `apply` — the exact anti-pattern the freeze doc
retired XPC for; (2) the "truth" specs (`docs/specs/*_PHASE2.md`) describe a pre-module-split tree and
document a **weaker µQC rule than the code enforces**; (3) the two-shard boot path now contradicts the
single-shard freeze; (4) several operator-facing docs state things that the code has already removed
(PQ classical cutoff, ECVRF, genesis 100M, `net_peerCount=0x2`). **Not ready for public testnet** until
the freeze docs and the env gate are reconciled; no rewrite is implied.

Top 5, in order:

1. `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` is read in the apply path (`state_engine/apply.rs:1238`) → per-node fork window. **S2, blocks public.**
2. `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md:15` documents the *old* µQC rule (`1/2 network`) and cap 64; code is `2/3 network` and cap 128 (`consensus/sortition.rs:89,155-164`). An audit against this spec approves the wrong protocol. **S2, blocks public/mainnet.**
3. `docs/specs/*_PHASE2.md` cite modules that do not exist (`consensus.rs`, `runtime.rs`, `state_engine.rs`, `rpc.rs`, `sharding.rs`, `bls.rs`, `crypto_privacy.rs`, `evm_adapter.rs`) and `main.rs` line numbers up to 8092 in a 35-line file. **S2, blocks public** (AGENTS.md §1 makes specs the truth).
4. Freeze doc says classical PQ handshakes live until H=300_000 and `{0}` is the only bootable shard set; code refuses classical at every height (`proto.rs:360-380`) and boots `{0,1}` without the hatch (`sharding/topology.rs:54-101`). **S2, blocks public.**
5. Header-anchor finality (`sync.rs:271`) and body finality (`sync.rs:850`, `runtime/apply.rs:993`) are documented as "one shared gate (A1)" but are two copies, and the header copy omits `binds_to_parent`. **S3, blocks mainnet.**

---

## Task 1 — Fake-code sweep (AGENTS.md §3)

`rg -n "todo!\(|unimplemented!\(|FIXME|XXX"` over `stellereum/{src,tests,benches,examples}` and
`infnode/`: **0 hits**. The harness regex (`scripts/harness_status.sh:29`) is honest for what it matches,
but it cannot see `TODO:`, dead lint-silencer functions, or stale `#[allow(dead_code)]` reasons.

| # | file:line | What it is | Reachable? | Sev | Blocks | Action |
|---|---|---|---|---|---|---|
| 1.1 | `infnode/crates/infnode/src/main.rs:1003` | `TODO: шифровать ключом владельца` — the `put` path derives the XChaCha20 key and nonce from **public** inputs (`blob_key_nonce`, `node.rs:7929-7938`: `blake3("infnode:blob-key:v1:{bucket}:{name}:{hash}")`). Ciphertext is trivially decryptable; it is obfuscation, not E2E encryption. | Yes — `infnode put` CLI path | S2 | mainnet (product claim) | Either encrypt the blob key to an owner key (the `key_box` mail path already does this) or stop calling the bucket path E2E and remove the TODO. |
| 1.2 | `stellereum/src/runtime/lanes.rs:515,530,552,560` | `#[allow(dead_code)] // GATE: VdfLane is scoped to lanes.rs here and wired into runtime/mod.rs in a follow-up integration step` — **the follow-up landed**: `VdfLane` is constructed and driven at `runtime/anchors.rs:217`, `runtime/mod.rs:197,613`, `anchors.rs:696`. Reason is stale; the allows hide the fact that the gate is no longer truthful. | No (dead allow only) | S4 | no | Delete the four `#[allow(dead_code)]` + stale GATE comments (or prove the items are still unused and write the real reason). |
| 1.3 | `infnode/crates/infnode/src/federation.rs:264` | `#[allow(dead_code)] fn _j(_x) -> Value { json!({}) }` — a function whose only purpose is to silence an unused import ("может пригодиться позже"). This is the "keep it for later" fake-code class AGENTS §3 bans. | No | S3 | no | Delete `_j` and the import. |
| 1.4 | `stellereum/src/bin/abi_codegen.rs:833` | `#[allow(dead_code)] fn _unused(_: &AbiEvent, _: &AbiParam) {}` — lint silencer with no purpose. | No (codegen bin) | S4 | no | Delete; fix the generated-code import instead. |
| 1.5 | `stellereum/src/mev_epoch.rs:1003` | `is_pq_transport_active(height)` ignores `height` and returns `true` (stub-by-design, documented at `:990-1006`). Not a defect, but every caller now pretends a gate still exists. | Yes | S4 | no | Keep (frozen schedule) or delete const+function together; do not leave it looking like a live gate. |
| 1.6 | `infnode/crates/infnode/src/keyring.rs:476` | `is_legacy() -> false` permanently (documented "no legacy arm"). Honest, but zero callers. | No | S4 | no | Delete with the next NodeId sweep. |
| 1.7 | `stellereum/src/bin/ledger_tool.rs:30-36` | `args[1]` taken as the DB path with no arg validation, `expect()` on `args[3]`. This is how `stellereum/--test-threads=2/{db,blobs,conf}` (a 16 KB sled store, dated 2026-11-17) got created: `scripts/test_parallel.sh:113` ran it as a test harness. | Yes (bad invocation creates a store in CWD) | S3 | no | Validate args (`--help` on unknown/`--`); delete the junk directory; fix `test_parallel.sh` skip list. |
| 1.8 | `stellereum/src/sync.rs:746-800` | `validate_sync_chain` / `validate_sync_chain_for_shard` are public "backward-compatible" entries with **zero production callers** (`rg` finds only tests). The live path uses `..._for_shard_with_sets_hashed` (`node/sync.rs:767`). The compat entries still carry the F5 property (one set for all heights). | No, but public API | S3 | mainnet | Deprecate/delete the single-set entries, or make them take `resolve_set`; otherwise the "fixed" F5 reappears the day someone calls the friendly name. |
| 1.9 | `stellereum/tests/hunt_f3f4f5_verify.rs:19,306` | Claims "F5 height-pinned validator set — STILL OPEN (documented limitation + `TODO(F5)` at src/sync.rs:270-281)". The TODO does not exist; `validate_sync_chain_with_sets` exists (`sync.rs:773`) and the replay path derives the set from the pre-state (`runtime/apply.rs:960-975`). The `#[ignore]` reason is false. | Test-only | S3 | no | Rewrite the header to "F5 closed on live paths; residual only in compat entries (1.8)"; keep the PoC ignored but accurate. |

---

## Task 2 — Silent-failure audit

Classified: acceptable (documented best-effort) vs finding. Scope: `let _ =`, `unwrap_or_default()`, `.ok()`
discard on consensus/state/API paths.

| # | file:line | Sink | Class | Sev | Blocks | Notes / action |
|---|---|---|---|---|---|---|
| 2.1 | `stellereum/src/node/bootstrap.rs:184` and `:932` | `let _ = storage.set_meta("genesis_state_root", …)` inside `match get_meta { _ => … }` | **Finding** | S3 | mainnet | The `_` arm also swallows `Err(..)` from the read. A corrupt/unreadable store is treated as "no genesis root" and overwritten, and a failed write is not reported. Fail closed on `Err`, and `?`/log the write. |
| 2.2 | `stellereum/src/node/bootstrap.rs:807` | `let _ = state_engine.credit_native_transfer(&faucet_addr, GENESIS_FAUCET_BALANCE).await` | **Finding** | S3 | mainnet | A silent genesis failure changes the genesis state root on that node only (funded vs unfunded faucet). Propagate the error; genesis construction must not have best-effort steps. |
| 2.3 | `stellereum/src/node/bootstrap.rs:1191` | `let _ = store.set_meta(FAUCET_STATE_META_KEY, bytes)` (persist hook) | **Finding** | S2 | public (faucet is already a documented public-testnet blocker) | In-memory per-address lifetime caps advance while the durable record does not. A restart resets caps → rotating-IP faucet drain gets easier, with no metric/log. Log + counter on failure; refuse the drip if the write fails. |
| 2.4 | `stellereum/src/node/upgrade_halt.rs:269` | `let _ = d.sync_all()` in `sync_parent` (directory fsync of the durable halt marker) | **Finding** | S3 | mainnet | The marker file is fsynced but the directory entry is not; on power loss the marker can vanish and the node restarts the **old** binary with no guard. Report the failure and refuse/retry the halt. |
| 2.5 | `stellereum/src/node/consensus_driver.rs:1285` | `let _ = rt.on_prevote(v.clone())` then broadcasts the same vote | **Finding** | S3 | mainnet | `on_prevote` returns `Result` (`runtime/consensus_step.rs:1268`); a rejected local vote is still gossiped. Counters/breaker state then disagree with what peers see. Log at WARN with the reason at minimum. |
| 2.6 | `stellereum/src/node/consensus_driver.rs:3143` | `bincode::serialize(&rt.cross_shard_replay_snapshot()).unwrap_or_default()` | **Finding** | S3 | mainnet | On failure this publishes an **empty cross-shard replay set** with the snapshot (the account path two functions later explicitly checks `bytes.is_empty()` and errors — this one does not). Treat empty as failure: skip the snapshot, emit `error!`. |
| 2.7 | `stellereum/src/storage.rs:3540`, `:3667` | `bincode::serialize(...).unwrap_or_default()` for `cnvrf_v3` and `accounts` snapshots | **Finding** | S3 | mainnet | Same pattern: a failed encode writes a zero-byte/empty snapshot instead of refusing. The restore root check catches it, but the node burns the height and may then prune the good snapshot. Return `Result` and skip the capture. |
| 2.8 | `stellereum/src/cli/handlers.rs:244` | `let _ = bridge.process_deposit(&dep_event)` in the `sim` demo path, followed by printing "Verified 2/3 Quorum" | **Finding** | S4 | no | The demo prints success regardless of the result. Propagate and print the error. |
| 2.9 | `stellereum/src/rpc/faucet.rs:498` | `bincode::serialize(&*st).unwrap_or_default()` | Acceptable (documented) | S4 | no | Restore path explicitly fails closed on unknown bytes (`faucet.rs:505-510`); still, empty-write is silent. Low priority. |
| 2.10 | `stellereum/src/mev_kem_registry.rs:404`, `stellereum/src/pq_registry.rs:483` | `let _ = self.apply_rotation(*id, now, true)` in the due-sweep | Acceptable (documented, unreachable failure) | S4 | no | Due-ness is derived from the same map; the only errors are `UnknownValidator`/`NoPendingRotation`/`RotationNotDue`, all impossible here. Comment is honest. Keep. |
| 2.11 | `stellereum/src/network.rs:2473,2527` | `let _ = tx.send(envelope)` local pubsub fan-out | Acceptable (best effort) | S4 | no | Receiver-less topic is normal; no state effect. |
| 2.12 | `stellereum/src/network.rs:1640-1839` | `serde_json::from_str(index).unwrap_or_default()` on DHT local-KV indexes | Acceptable, but undocumented | S4 | no | Rebuildable cache; a corrupt index silently becomes "empty" and re-publishes. Add one comment (or a metric) so operators can tell corruption from a cold index. |
| 2.13 | `stellereum/src/node/consensus_driver.rs:3237` | account snapshot encode `unwrap_or_default()` | Acceptable (documented) | S4 | no | The very next lines check `bytes.is_empty()` and `tracing::error!`. This is the pattern 2.6/2.7 should copy. |

---

## Task 3 — Panic audit (non-test, request/consensus paths)

Method: counted `unwrap()/expect()/panic!()` before the first `#[cfg(test)]` in each hot file, then read
every survivor. Result: **no input-reachable panic in consensus, state-apply, sync or RPC** was found.

| # | file:line | Construct | Verdict | Sev | Blocks |
|---|---|---|---|---|---|
| 3.1 | `stellereum/src/runtime/apply.rs:171,191,192` | `expect("lane just spawned")`, `expect("apply worker lives…")`, `rx.await.expect("apply worker answers every job")` | Invariant, but it converts a panic **inside** the apply worker (any bug, including a future input-triggered one) into a process-wide panic on every node. Fail-closed, no attribution. | S3 | mainnet |
| 3.2 | `stellereum/src/state_engine/settlement.rs:331,386,412,461,1005,1014,1041` | `escrow_map.get_mut(&key).unwrap()` in the CLOB settlement/apply path | Safe today: each is preceded by `is_some_and`/`map(...)` on the **same write guard with no await between check and use**. Fragile: one inserted `.await` turns it into a block-apply panic (DoS). | S3 | mainnet |
| 3.3 | `stellereum/src/consensus/types.rs:1228` | `slots[i].as_ref().expect("slot present during the signature screen")` | Safe: `indices` come from the same `slots`. | S4 | no |
| 3.4 | `stellereum/src/consensus/engine.rs:644,647,659,674,686` | `expect("slot present …")`, `expect("every input index is admitted exactly once")` | Safe: `order` is `0..len`, slots are all `Some` until taken in the same loop. | S4 | no |
| 3.5 | `stellereum/src/state_engine/apply.rs:3567,3581` | `expect("recipient existence checked above")` | Safe: `contains_key` immediately before, same map, no await. | S4 | no |
| 3.6 | `stellereum/src/state_engine/types.rs:81` | `bincode::serialize(&ActorSendBody{..}).expect("actor body serializes")` | Practically unreachable (fixed ints + Vec of unit enums; bincode only fails on allocation). | S4 | no |
| 3.7 | `stellereum/src/rpc/writes.rs:860` | `_ => unreachable!()` in the native-op dispatch helper | Only panics if a caller passes a variant the helper never accepts. Internal, but a panic in an RPC handler is a connection kill. | S4 | no |
| 3.8 | `stellereum/src/sync.rs:1758` | `s.expect("all slots filled")` | Guarded by `position(|s| s.is_none())` check six lines above. | S4 | no |
| 3.9 | `infnode/crates/infnode/src/node.rs:7866` | `cipher.encrypt(...).expect("e2e encrypt")` | AEAD encrypt fails only on >2^32-byte input or bad key; request path would panic. Prefer `?`. | S4 | no |

Deliberately not listed as findings: `consensus/sortition.rs:381` (`hash[0..8]` on a 32-byte digest),
`rpc/reads.rs:67,773` (length-checked), `explorer.rs:1732` (guarded by `payload.is_empty()`),
`consensus_net.rs:2448` (length-checked), `network.rs:2598` (`[..8]` on a `[u8;32]`).

No panic/DoS finding. The two worth fixing anyway are 3.1 (apply-lane attribution) and 3.2 (fragile unwraps
in the CLOB path).

---

## Task 4 — Doc/code drift (statements that are FALSE now)

This is the biggest defect class. Two kinds: (a) **stale facts** that an operator/auditor would act on;
(b) **structural staleness** — the whole `*_PHASE2` spec set was written against a single-file tree that
was split in `9607dbd85` and stripped of classical crypto in `3d59b9dce`.

### 4a. Substantive false claims (fix first)

| # | Doc:line | Claim | Truth at HEAD | Sev | Blocks |
|---|---|---|---|---|---|
| 4.1 | `docs/PUBLIC_TESTNET_CODE_GAPS.md:15` | PQ handshake: classical lives until H=300_000, mixed window with WARN+counter | `PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`, the mixed window and the counter were **deleted**; classical is refused at every height and `STELL_INF_PQ_HANDSHAKE` is parsed-and-ignored (`infnode/.../proto.rs:357-380`). | S2 | public |
| 4.2 | `docs/PUBLIC_TESTNET_CODE_GAPS.md:16` | MEV PQ transport sleeps until H=10_000, flipped by `PREFER_PQ_MEV_TRANSPORT` | `is_pq_transport_active` returns `true` unconditionally (`mev_epoch.rs:1003-1006`); the `PREFER_PQ_MEV_TRANSPORT` **const no longer exists** (only a prose mention in `state_engine/mod.rs:71`). | S2 | public |
| 4.3 | `docs/PUBLIC_TESTNET_CODE_GAPS.md:17` | ECVRF is dead code under a marker; CN-VRF is a sandbox with no consensus import | ECVRF is **deleted** — `vrf.rs` is 133 lines of lottery math. CN-VRF **is** imported by `commitment.rs:1919+`, `storage.rs:4952`, `sync.rs:2781`, `runtime/anchors.rs`, and the v3 sortition gate exists (`consensus/sortition.rs:552-576`). | S2 | public |
| 4.4 | `docs/PUBLIC_TESTNET_CODE_GAPS.md:18` | Boot guard: `STELL_SHARDS != {0}` without `STELL_EXPERIMENTAL_SHARDS=1` refuses startup | `check_workchain_boot_guard_with_hatch` accepts `{0,1}` **without the hatch** (`sharding/topology.rs:54-101`). The freeze document and the code disagree on the public protocol's shard set. | S2 | public |
| 4.5 | `docs/PUBLIC_TESTNET_CODE_GAPS.md:23` | "constant in code + env-override for tests" for H | There is no env override; test overrides are thread-locals compiled only under `cfg(any(test, debug_assertions))` (`consensus/sortition.rs:194-220`, `governance.rs:84-114`). | S4 | no |
| 4.6 | `docs/TESTNET_COMPLETENESS.md:97-99,116` | `PQ_CLASSICAL_REFUSE_AFTER_HEIGHT = 300_000`, enforced/fail-closed; `PREFER_PQ_MEV_TRANSPORT=false` | Same as 4.1/4.2: const gone, gate gone, tests cited (`pq_handshake_tests.rs:1027-1168`) test a deleted policy. | S2 | public |
| 4.7 | `docs/COMPLETENESS_GAP_ANALYSIS.md:80,272` | Genesis credits 100M STELL per validator by direct write "bypassing the mint counter, with no assertion that N×100M+faucet ≤ 1B"; "with 11 validators the chain starts above its cap" | `GENESIS_VALIDATOR_BALANCE = 1_000_000 STELL` (`node/policy.rs:369`), genesis supply is asserted at boot and **refuses** if over cap (`node/bootstrap.rs:727-739`), and it is folded into the minted counter on first reservation (`state_engine/accounts.rs:1859-1875`). | S2 | public (it is handed to auditors as the tokenomics gap) |
| 4.8 | `docs/COMPLETENESS_GAP_ANALYSIS.md:74,198` | `net_peerCount` returns constant `"0x2"`; `eth_getCode` always `0x` | `net_peerCount` serves an observed peer count (`rpc/eth.rs:683-691`); `eth_getCode` serves account/contract code (`rpc/eth.rs:767` → `evm_adapter/adapter.rs:2482-2497`). The old fake-response gap is closed. | S2 | mainnet |
| 4.9 | `docs/COMPLETENESS_GAP_ANALYSIS.md:23,90,164` | No `.github` directory / no hosted CI at all | `stellereum/.github/workflows/ci.yml` exists (lint + build + test jobs). The root has no `.github`, but "CI is absent" is false for the core crate. | S3 | no |
| 4.10 | `docs/COMPLETENESS_GAP_ANALYSIS.md:19` table | "`unjail` has no opcode, no RPC, no wallet command" (and commission/redelegate dead ends) | Unjail **is** wired: `OpCode::SysCallUnjail` (`svm.rs:1124,2149`), applied via `apply_staking_unjail_ops`. Redelegate and commission-change remain unwired. Split the claim. | S3 | mainnet |
| 4.11 | `docs/UPGRADE_AND_RECOVERY.md:40-41,155-156,850` | "`upgrade_plan` is **not** in the commitment digest (`commitment.rs:726-757` has no arm)" | The arm exists at `commitment.rs:784-788` (presence, name, height, sha256) — `COMPLETENESS_GAP_ANALYSIS.md:471-473` says the same. The two docs contradict each other. | S2 | mainnet |
| 4.12 | `docs/UPGRADE_AND_RECOVERY.md:70-82` | "Ten constants" is the inventory of every `*_ACTIVATION_HEIGHT` | There are **thirteen** gate constants, including `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX` (`governance.rs:80`), `CHAIN_BINDING_ACTIVATION_HEIGHT` (`chain_binding.rs:48`) and `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` (`zkml_attestation.rs:144`). An operator reading the old inventory missed the upgrade-execution gate. | S3 | mainnet |
| 4.13 | `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md:15` | µQC power rule = `max(2/3 committee, 1/2 network+1)`, committee cap 64 | Code: `max(2/3 committee, 2/3 network)` (`consensus/sortition.rs:155-164`) and `MICRO_COMMITTEE_MAX_SIZE = 128` (`:89`). The code comment explicitly documents the old 1/2 rule as a **broken** rule (`sortition.rs:110-135`). | S1 (audit artefact is wrong about the safety threshold) | public + mainnet |
| 4.14 | `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md:37` | Round-timeout base comes from `STELL_ROUND_TIMEOUT_MS`, must match across validators | Env removed; base is `FROZEN_ROUND_TIMEOUT_BASE_MS = 3000` (`consensus/sortition.rs:709-710`; `node/consensus_driver.rs:879-881`). | S2 | public |
| 4.15 | `docs/specs/02_CRYPTO_AND_PQ_PHASE2.md:25,56,60-66` | `STELL_PURE_PQ` is a switch; BLS (`bls.rs`, `DEFAULT_BLS_ACTIVATION_HEIGHT`) and ECVRF (`STELL_VRF_ACTIVATION_HEIGHT`, `vrf.rs:128`) exist | `bls.rs` deleted; ECVRF deleted; `vrf.rs` is 133 lines with no activation type. `STELL_PURE_PQ` is parsed-and-ignored on the node (override `Some(true)` at `node/consensus_driver.rs:94`). | S2 | public |
| 4.16 | `docs/specs/02_CRYPTO_AND_PQ_PHASE2.md:129-130` | "Sandbox status VERIFIED: zero `cn_vrf::` callers in `stellereum/src`", "unwired (no production call site)" | `cn_vrf` is consumed by `commitment.rs`, `storage.rs`, `sync.rs`, `runtime/anchors.rs`; the v3 gate is in production code (`sortition.rs:552-576`). | S2 | public |
| 4.17 | `docs/PQ_CN_VRF_SPEC.md:661-662,721,728` | `VrfActivation::Disabled` posture at `vrf.rs:169-175`, `STELL_VRF_ACTIVATION_HEIGHT` at `vrf.rs:126`, CNVRF gate at `sortition.rs:507`, `EPOCH_LEN` at `cn_vrf.rs:62` | `vrf.rs` is 133 lines and has none of those; gate is `sortition.rs:552`; `EPOCH_LEN` is `cn_vrf.rs:65`. | S3 | mainnet |
| 4.18 | `stellereum/src/chain_binding.rs:101,128` | RPC error text tells wallets "see docs/PLAN-BINDING.md" | `docs/PLAN-BINDING.md` does not exist. This string is served to users on refusal. | S3 | public (wallet onboarding) |
| 4.19 | `docs/PUBLIC_TESTNET_CODE_GAPS.md:42-43` | Audit package includes `docs/program/` and `docs/PQ_VRF_FRONTIER_V2.md` | Neither path exists. | S4 | no |

### 4b. Structural staleness of `docs/specs/*_PHASE2.md` (one root cause, many lines)

Commit `9607dbd85` split `consensus.rs` → `consensus/{mod,engine,types,sortition,qc_split,rotation}.rs`
and `runtime.rs` → `runtime/{mod,apply,consensus_step,anchors,lanes,cluster,mev_sync}.rs`; `state_engine.rs`,
`sharding.rs`, `rpc.rs`, `evm_adapter.rs` are directories now; `bls.rs` and `crypto_privacy.rs` are gone;
`main.rs` is **35 lines** (all CLI in `cli/`, all node logic in `node/`).

Every `file:line` in those specs is therefore unresolvable. Representative lines (all **S2**, **blocks public**,
because AGENTS.md §1 makes `docs/specs/` the technical truth):

| Doc | Lines | What breaks |
|---|---|---|
| `docs/specs/00_PROJECT_MAP_PHASE2.md` | `:20` | Points at missing `docs/VRF_ACTIVATION_PLAN.md` and `vrf.rs:87,132-150` (no env exists). |
| `docs/specs/01_ARCHITECTURE_OVERVIEW_PHASE2.md` | `:25,31,34,35,39,42,46,48,51,57-66` | Module map lists `bls.rs`, `consensus.rs`, `crypto_privacy.rs`, `evm_adapter.rs`, `runtime.rs`, `rpc.rs`, `state_engine.rs`, `sharding.rs`; frozen-core line refs (`sharding.rs:4890`, `consensus.rs:2806`) invalid. |
| `docs/specs/02_CRYPTO_AND_PQ_PHASE2.md` | `:3-4,54-66,109-130` | Source list includes `bls.rs`; all Falcon/BLS/ECVRF line numbers shifted; "35-method"/`cn_vrf` claims stale (see 4.15-4.16). |
| `docs/specs/03_VM_AND_EXECUTION_PHASE2.md` | `:3-5,27-64` | Sources `state_engine.rs`, `runtime.rs`, `evm_adapter.rs`; entries `runtime.rs:8184`, `state_engine.rs:6437`, `rpc.rs:274` all invalid. |
| `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md` | `:3,9-13,41-42` | `consensus.rs:3905` etc; `main.rs:974-978`/`:150-156` in a 35-line file. |
| `docs/UPGRADE_AND_RECOVERY.md` | `:67,88` | **Fixed post-wave (`24e2a1dca`):** gate inventory is now `0/0/0` for compact/XPC/GOV_OPS, `UPGRADE_EXEC` is listed, and catch-up says 30 s backstop. |
| `docs/COMPLETENESS_GAP_ANALYSIS.md` | `:54,55,107,239,277` | **Fixed post-wave (`24e2a1dca`):** compact/XPC/governance are active from genesis; only the remaining `u64::MAX` gates are listed. |

**Recommended fix, one PR:** regenerate the specs from the current tree (or add a "superseded by
`00_PROJECT_MAP.md` + `CODE_INDEX.md`" banner and delete the stale ones). Do not hand-patch line numbers;
they will drift again. Until then, treat `docs/specs/` as historical, not truth.

---

## Task 5 — Gate values and env switches

### 5a. Every `*_ACTIVATION_HEIGHT`

All are documented in code. `COMPACT_GOSSIP`, `XPC` and `GOV_OPS` are active at `0`; `PQ_TRANSPORT_H` is a legacy schedule entry. The rest are `u64::MAX`/never.

| Constant | Value | Declared | Reader | Consensus effect | Verdict |
|---|---|---|---|---|---|
| `QC_SPLIT_ACTIVATION_HEIGHT` | `u64::MAX` | `consensus/sortition.rs:179` | `qc_split_active_at` `:231` | µQC advisory vs finality split | off, documented |
| `BEACON_DRAW_ACTIVATION_HEIGHT` | `u64::MAX` | `:464` | `:473` | XMSS beacon committee draw | off, documented |
| `CNVRF_V3_ACTIVATION_HEIGHT` | `u64::MAX` | `:552` | `:568` | CN-VRF v3 sortition/proposer | off, documented |
| `COMPACT_GOSSIP_ACTIVATION_HEIGHT` | `0` | `consensus_net.rs:2097` | `compact_gossip_active` | compact proposal gossip + compact µQC codec | **active from genesis**; proposal path wired end to end, µQC emit/admit call sites deferred |
| `EMISSIONCapEXACT_ACTIVATION_HEIGHT` | `u64::MAX` | `tokenomics.rs:55` | `:395` | emission schedule | off, documented |
| `PQ_TRANSPORT_H_ACTIVATION_HEIGHT` | `10_000` | `mev_epoch.rs:995` | `:1003` | **none** — function returns `true` always | retained for frozen schedule only |
| `XPC_ACTIVATION_HEIGHT` | `0` | `xshard2pc.rs:146` | `XpcActivation::from_chain_spec` | cross-shard 2PC | **active from genesis**; env ignored with WARN (`node/policy.rs:1016-1047`) |
| `MEV_RESHARE_ACTIVATION_HEIGHT` | `u64::MAX` | `mev_epoch.rs:1703` | `:1715` | proactive reshare | off, documented |
| `GOV_OPS_ACTIVATION_HEIGHT` | `0` | `governance.rs:151` | `gov_ops_active_at` | block-carried governance | **active from genesis**; propose/vote apply, deterministic finalize+execute |
| `UPGRADE_EXEC_ACTIVATION_HEIGHT` | `u64::MAX` | `governance.rs:80` | `upgrade_exec_active_at` | upgrade sweep | off, documented; **not in `chain_spec`**; blocks `SoftwareUpgrade`/`CancelUpgrade` execution only |
| `SPRT_TIER3_ACTIVATION_HEIGHT` | `u64::MAX` | `oracle.rs:205` | `:224` | advisory oracle only | off, documented |
| `CHAIN_BINDING_ACTIVATION_HEIGHT` | `CHAIN_BINDING_NEVER` | `chain_binding.rs:48` | `check_admission*` | chain-binding rollout | never; the env form is the remaining consensus switch |
| `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` | `u64::MAX` | `zkml_attestation.rs:144` | context-bound transcript | zkML context binding | off, opt-in seam |

`chain_spec::current_activation_schedule()` lists 7 (`chain_spec.rs:130-180`): QC split, beacon, CN-VRF,
compact, emission, PQ transport, XPC. Missing from the operator-visible schedule: `MEV_RESHARE`, `GOV_OPS`,
`UPGRADE_EXEC`, `SPRT_TIER3`, `CHAIN_BINDING`, `ZKML_CONTEXT_BINDING`. Acceptable only if the schedule is
explicitly labelled "not exhaustive" — it is not. **S3, mainnet.**

Theoretical nit (not a finding): every gate uses `height >= CONST`, so a chain that reached height
`u64::MAX` would activate all of them for exactly one block. Unreachable (>10^19 blocks); `tokenomics`
special-cases it, the others do not. No action.

### 5b. Env switches that change protocol behaviour

The freeze rule is "public gets one fixed protocol, not a constructor of env flags"
(`docs/PUBLIC_TESTNET_CODE_GAPS.md:3`). Violations:

| # | Env | Read where | Can change consensus? | Sev | Blocks | Action |
|---|---|---|---|---|---|---|
| 5.1 | `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` | **`state_engine/apply.rs:1238`**, `state_engine/parallel.rs:804-845`, `mempool.rs:1882`, `rpc/writes.rs:37`, `consensus/types.rs:110` | **Yes, directly.** `check_admission_from_env` is called per transaction inside the apply path; the value is read from the process env, so two nodes with different env admit different transactions at the same height → different state roots. This is the exact pattern XPC was retired for (`node/policy.rs:876-905`). | **S2** | **public** | Replace with a chain-spec/compile-time height (or a genesis-committed parameter). If a rollout height is needed, put it in the committed state, not the environment. Do this before public testnet. |
| 5.2 | `STELL_GOV_ALLOW_MULTINODE_WRITES` | `governance.rs:993-1015` (`is_gov_multinode_escape`) | Indirectly: allows a local-only RPC governance mutation on N>1, which every peer that did not see it will not replicate → fork. Code says so in capitals (`governance.rs:985-991`). | S3 | mainnet | Keep refused; it is documented as a fork switch. Consider compile-time gating it out of release. |
| 5.3 | `STELL_PARALLEL_EXEC` | `node/bootstrap.rs:492`, `node/consensus_driver.rs:97` | Selects the execution engine; determinism is claimed and tested. If any divergence bug exists, this becomes a fork switch. | S4 | no | Keep, but pin parity in the gate (exists: `*_parity_tests.rs`). |
| 5.4 | `STELL_SHARDS` | `node/bootstrap.rs:506-545` | Changes which chains this process runs (and genesis/store layout). `{0,1}` now boots **without** the experimental hatch (4.4). | S2 | public | Resolve the policy: either single-shard only (restore the guard) or document `{0,1}` as the frozen public topology in the freeze doc. |
| 5.5 | `STELL_CHAIN_ID` | `zkml.rs:197` → cached `FROZEN_CHAIN_ID` | Changes block/vote preimages (new network). Deployment input, documented. | S4 | no | None. |
| 5.6 | `STELL_FAUCET_KEY` / `_FILE` / `STELL_DEV_UNSAFE_TESTKEY` | `node/bootstrap.rs:1138-1200` | Changes the genesis faucet account → genesis root. Fails loudly on mismatch. | S3 | public (key-handling policy) | Already gated; ensure `STELL_DEV_UNSAFE_TESTKEY` is absent from public images. |
| 5.7 | `STELL_PURE_PQ` | `post_quantum.rs:89-107` | Node always installs `Some(true)` override (`consensus_driver.rs:94`), so env is dead on the node; library/sim default still reads env. | S4 | no | Document as dead, or remove (docs still sell it as a switch — 4.15). |
| 5.8 | `STELL_AUTO_UPGRADE`, timeouts (`STELL_MIN_BLOCK_MS`, `STELL_TICK_MS`, `STELL_DOWN_PROPOSER_TIMEOUT_MS`, `STELL_ROUND_ZERO_TIMEOUT_MS`), RPC/rate/mempool caps, retention | various | Liveness/ops only. Timeouts must be locally chosen; a proposal that arrives first wins. | S4 | no | None. |

Note on test-only activation overrides (`set_qc_split_activation_override`, `set_upgrade_exec_activation_override`,
`set_cnvrf_v3_activation_height_for_tests`, `enable_gov_ops_for_tests`, `enable_hashpool_for_tests`):
the first three are correctly `cfg(any(test, debug_assertions))`; `enable_gov_ops_for_tests`
(`state_engine/apply.rs:3025`) and `enable_hashpool_for_tests` (`:3036`) exist **in release builds** as
public library APIs. Grep proves no live caller, so this is not currently exploitable — but it is a latent
protocol switch in a shipped library. **S4, no.** Gate them with `cfg(any(test, debug_assertions))`.

---

## Task 6 — Test coverage gaps

Coverage is genuinely broad: 328 integration test files, 1338 lib tests, and dedicated suites for
byzantine, partition, catch-up, snapshots, CLOB, bridge, MEV, 2PC, governance, upgrade halt.
Named gaps are only where a consensus/state-risk path has **zero direct** references (verified by
grepping the symbol in `stellereum/tests` and `src/*/tests`):

| # | Path | Evidence | Risk | Sev | Blocks |
|---|---|---|---|---|---|
| 6.1 | `runtime/mev_sync.rs::sealed_meta_matches` | 0 test files reference it | Seal/plaintext binding: a wrong result admits a tx under another seal. | S3 | mainnet |
| 6.2 | `node/sync.rs::retro_publish_pass` (`:1056`) | 0 references; only called from `consensus_driver.rs:1418` | Retro body re-publication is the liveness recovery path that broke live before; a regression is silent (no bodies → heal fails). | S3 | mainnet |
| 6.3 | `node/sync.rs::refresh_validator_set_from_fresh_snapshot` (`:414`) | 0 references | Derives the in-force validator set after snapshot restore. A wrong set = verifying QCs against the wrong quorum. | S2 | mainnet |
| 6.4 | `node/consensus_driver.rs` as a unit | No `#[cfg(test)]` in the file; only cluster/integration tests | 3 000 lines of tick/advance/halt/straggler logic with no direct tests. Most failures here are liveness, not safety, which is why it is S3 and not S2. | S3 | mainnet |
| 6.5 | `state_engine/settlement.rs::clob_quote_native` / `pmm_buy` internals | Exercised indirectly by CLOB/PMM suites; no direct unit on the native-quote branch | The unwraps in 3.2 are exactly here. A direct test that drives a drained escrow would pin the invariant. | S3 | mainnet |
| 6.6 | `node/upgrade_halt.rs` | 1 integration file (`upgrade_halt_tests.rs`) | Covered; listed only because the fsync failure (2.4) is untested. | S4 | no |

Covered (do not "add tests for coverage"): `consensus/{engine,types,sortition}`, `runtime/consensus_step`,
`xshard2pc`, `chain_binding`, `snapshot_cadence`, `parallel_exec`, `bridge`, `state_engine/gov_ops`,
`state_engine/parallel`, `mempool` (34 files reference `on_prevote`, 27 `try_finalize`).

---

## Task 7 — Module boundaries

`bash scripts/check_import_graph.sh` → **PASS**, 0 forbidden imports (35 core files, 664 sources scanned;
exit 0, run 2026-11-18). The script's core list is `consensus, consensus_net, sharding, state_engine,
runtime, mempool, staking, xshard2pc, chain, sync` and its edge list `rpc, explorer, wallet,
wallet_signing, light_client_cli, cli, node`.

| # | Finding | Evidence | Sev | Blocks | Action |
|---|---|---|---|---|---|
| 7.1 | **Layering inversion not covered by the script:** `evm_adapter` (execution/translation layer) imports `crate::rpc::RpcState` and exposes JSON-RPC entry points. | `evm_adapter/adapter.rs:2`, `:1359,1692,2331,2569,2640...` | S3 | mainnet | Move the `*_rpc(RpcState, …)` wrappers into `rpc/eth.rs`; keep `evm_adapter` state-engine-only. Add `evm_adapter` to the script's core list. |
| 7.2 | **Sandbox crypto reaches into node key custody:** `cn_vrf` (declared "pure sandbox, imports nothing") imports `crate::node_keys` for passphrase/plaintext-key handling. | `cn_vrf.rs:1754-1765`; purity claim `cn_vrf.rs:11-15` | S3 | mainnet | Move the custody helper into `node_keys` (or a `keyfile` module) and pass bytes in. Keeps the sandbox diff-able for audit. |
| 7.3 | **Duplicated finality gate, divergent:** `verify_finality_for_header` (header-anchor path, `sync.rs:271-307`, called at `:437,636`) and the inline body gate (`sync.rs:850-1000`, and `runtime/apply.rs:933-1000`, `runtime/consensus_step.rs:2240-2290`) encode the same checks. The doc at `sync.rs:267-270` says "shared … so the two can never drift (A1)". **They are not shared**, and the header path omits `qc.binds_to_parent` (`consensus/types.rs:2330`) which both body paths enforce. | `sync.rs:271` vs `:954`, `runtime/apply.rs:993`, `runtime/consensus_step.rs:2256` | S3 | mainnet (needs 2/3 network either way, so not exploitable by <1/3, but the asymmetry is a real defence-in-depth hole and falsifies the A1 claim) | Make `verify_finality_for_header` call the same inner predicate as the body path (including `binds_to_parent`), or add the check and a test that a µQC with a foreign sortition parent is refused on the anchor path too. |
| 7.4 | **Two quorum curves with different rounding (documented, intentional):** bridge `floor((2n+2)/3)` vs consensus `floor(2n/3)+1`. They disagree at n=3 (2 vs 3) and n=6 (4 vs 5). | `bridge.rs:535,544`; pinned test `bridge.rs:2277-2331` | S4 (policy re-check, not a bug) | mainnet | Keep the separation, but write the *why* (external relayer set vs BFT set) in `PROTOCOL.md`; an auditor will otherwise read it as an off-by-one. |
| 7.5 | Quorum/power math is otherwise centralised: `ValidatorSet::quorum_power` (`consensus/types.rs:748`) → `consensus_quorum_min` (`sortition.rs:24`); µQC thresholds delegate (`:44,63,155`); `sync`/`light_client`/`apply` all call `validators.quorum_power()`. No duplicate rounding found. | — | — | — | No action. |

---

## What is clean (for the record)

- Zero `todo!`/`unimplemented!`/`FIXME`/`XXX`; clippy `-D warnings` green in both workspaces.
- No reachable input-driven panic found in consensus/state/sync/RPC; every index/slice on peer bytes is
  length-guarded.
- All ten `u64::MAX` gates are documented with a GATE reason and a rollout procedure; test-only overrides
  are thread-local and (mostly) `cfg`-gated.
- Quorum math has one definition; the two "duplicate" curves are deliberately domain-separated and pinned.
- Module isolation script passes; no core module imports UI/wallet/RPC.

## Housekeeping (not findings, but AGENTS.md §1 violations)

Root contains `COMPREHENSIVE_AUDIT_REPORT.md` (55 KB), `FEATURES.md`, `STELLEREUM_BLOCKCHAIN_FIXES.md`,
`pl.txt` (32 KB), `stellereum-math.zip`, and `stellereum/ --test-threads=2/` data store. AGENTS.md §1 says
progress is tests + machine-generated `STATUS.md`, everything else `.archive/`. Move or delete; the junk
store is also evidence of 1.7.
