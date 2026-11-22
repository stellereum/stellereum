# ROADMAP — what needs doing (HDAE canonical, curated, 2026-10-29)

Maintained by the lead only. Mark `[x]` with gate-output hash/date, never on intent.
Machine state: `STATUS.md`. Features: `FEATURES.md` (113 E2E rows). Why: `docs/specs/`.

## Remote topology (all private, `immtes/`)

Monorepo stays LOCAL (dev home). Pushed mirrors, branch per milestone
(`hdae-baseline-*, hdae-enterprise-*`; main/agent branches never touched):

| repo | content |
|---|---|
| `stellereum` | core node (`stellereum/`) |
| `infnode` | network (renamed from infmail-valid-backend) |
| `stellereum-contracts` | contracts + contract-sdk (renamed, was `stellereum-sdk`) |
| `stell-wallet` | wallet CLI |
| `stellereum-indexer` | indexer |
| `stellereum-hdae` | shared infra: AGENTS, specs, gates, matrix, handoffs, docs (main branch) |

No remote yet: standalone `stellereum-sdk/` (client tx-builders, zero in-tree
consumers — external-facing, publish candidate), `scripts/tools/stelops`,
`explorer-site`. Monorepo local commits: baseline → rename → enterprise → fmt.

## Done (verified)

- [x] clippy `-D warnings` 0/0 all 7 workspaces (holds after wave-2 fixes)
- [x] Full suite green: stellereum lib 1040/1040, infmail, e2e, wallet, indexer, sdk, stelops
- [x] Security wave-2 fixes (`cffef70`, pushed `hdae-fixes2-*`):
  SDK `caller()`/`value()`+mocks; EVM prefix bind, ABI trailing strictness,
  calldata cap, short-word strictness, gas-floor honoring; gov snapshot
  weights + proposer lock; wallet secret-bound migration (legacy decrypt
  removed); indexer LIKE-escape, reorg replace+invalidate, verify auth,
  offset cap, hash NOCASE. Deferred (structural, tracked): oracle TWAP
  anchor (O1), contract auth rewrite (CT-P0), wallet notes UX migration note.
- [x] Structural wave (`9d2bfbd`, pushed `hdae-structural-2026-10-30` to core):
  replay height-gate (default-off) + wallet pre-check; VRF sortition gate
  (default-off, byte-identical pre-activation); BLS PoP strict parse
  (default-off); audit package refreshed (repro green except 2 fixed
  estimate-contract tests).
- [ ] Full feature-matrix re-run (113 rows + new suites)
- [x] Polish wave 1 (details in git history): RPC drift, crypto/state pins
- [x] Session bloat archived (29 files), specs 00-04 + isolation plan written
- [x] Gate scripts + justfile + agents infra + AGENTS.md constitution
- [x] Prune timers on all 4 nodes, snapshot fresh, divergence-watch pattern
- [x] Stale-test repairs: wallet Falcon determinism pin, p3 halt-height race pin

## P0 — speed + repo bootstrap
- [x] Deploy VEL fixes (prebuild + vote pipeline, build `573d86f5`) to all 4 nodes
  (2026-10-29 rolling, `.old` kept): no divergence/panics, all finalizing.
  Tempo 8.2 s/blk (dirty window) → ~2.5 s/blk sustained; rounds 6200+ → single
  digits converging. r0 still rarely decides (slow-proposer slots + WAN).
- [x] `git init` + baseline commit (833c71e); nested repos absorbed (history in `.archive/nested-history.txt`)
- [x] Per-part private remotes carry `hdae-baseline-2026-10-29` (main/agent branches untouched):
  `immtes/stellereum`, `immtes/infnode` (renamed from infmail-valid-backend),
  `immtes/stellereum-contracts`, `immtes/stell-wallet`, `immtes/stellereum-indexer`
- [ ] Hour tempo verdict (meter running `/tmp/opencode/tempo-hour.log`): sustained
  mean/p50/p99 + views/block. r0-decide rate: slow-proposer slots (C/D 1-vCPU) vs misses.
- [ ] Contract auth redesign (audit B-CT P0): the 4 wasm contracts authenticate
  NOTHING (integer `from`/`owner`/`caller_id` replayable; `host.caller` exists
  in node but unused). Failing `poc_p0_*` tests are the acceptance criteria.
  SDK `caller()`/`value()` + mocks landed; contracts marked demo-grade.

## P1 — product gaps

- [ ] Workchain: execute PARK (S4 runbook) or fund + serve shard-1 RPC (currently wedged/empty).
- [ ] Live demos (code exists, never run live): split, 2PC finalize, DKG sealed round-trip.
- [ ] Legacy replay-protection rollout (envelopes).
- [ ] VRF live path (parent-hash sortition is canonical; CN-VRF v3 is gate-off). BLS was deleted with the FULL-PQ wipe — drop the old PoP item.

## P2 — hygiene

- [x] `cargo fmt` whole tree (commit `fc028d9`, mechanical, checks green)
- [ ] Flip fmt to hard gate (currently advisory in `verify_testnet_ideal.sh`).
- [ ] Install: `just`, `cargo-nextest`, `sccache`/`mold` (all absent; scripts degrade gracefully).
- [ ] System disk 86% (outside repo scope — operator level).

## Out of scope (org level, not agents)

- External security audit (mainnet/listing blocker), grants/accelerators, mainnet checklist.

## Audit status — 2026-10-30 (AUDITPREP, docs+script only)

- [x] audit-repro catalogue verified current 2026-10-30: 79 suites + 7 fuzz targets all resolve, `cargo build --tests --all-targets` green 44.36s (log `/tmp/opencode/audit-repro-nofuzz.log`, fuzz `/tmp/opencode/audit-fuzz.log`)
- [x] Audit package refreshed 2026-10-30: brief provenance → `4d0d539` (src 164081 lines/58 files/55 modules), workspace renames (infnode, contract-sdk), VEL build `573d86f5`; KI-36/build/harness moved to KNOWN_ISSUES §N (verified in code + green run)
- [ ] audit-repro red: `audit_rpc_evm_closeout` F4 2 tests (KI-37, estimate floor-vs-pure contract mismatch, other agents) — gate NOT green, no check weakened to green it
- [ ] Open items recorded KNOWN_ISSUES §M 2026-10-30: KI-37 F4, KI-38 CT-P0 rewrite (acceptance: failing `poc_p0_*`), KI-39 wallet UX note, KI-40 r0-decide rate (meter pending), KI-41 workchain PARK/fund (unprobed, refusal logged)

---

## Active Roadmap — Ruleset v7, Jitter Optimization & Rollout (2026-11-21)

Canonical blueprint: `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`.
Defect registry: `docs/OPEN_DEFECTS.md` (zero-backlog rule: every item ends `FIXED`, `BY DESIGN`, or `SEPARATE SYSTEM`).

### Completed Baselines (`origin/main` & `origin/full-pq-testnet-2026-11-16`)
- [x] **W0 + P0 + Isolated W1/W2/W4 crates (`e31968725..74d641dba`)**: `SafetyAuthority` + `SafetyRecordStore` + `O(1)` cross-kind guard + `RESTART-SPLIT` + `PROPOSER VALUE PREFERENCE` + security/faucet/explorer/mempool/light_client fixes + `OPT-HNTT`/`OPT-TXHASH-BATCH`/`OPT-RECEIPT-INDEX`/`OPT-FINALIZED-CACHE`/`OPT-ESTIMATE-FEE`/`OPT-CLIENT-IP-CONFIG`/`OPT-SUBSCRIPTION-HUB` + Falcon FIPS-206 compression retry + `data_plane_rs` + `snapshot_v4` + `indexer` + `ledger-tool` + `infnode` EC.
- [x] **R1 (`a8d8ca6cb`)**: Execution atomicity (`OpCode::Halt` barriers, `SysCallCallContractArgs`/`SysCallSubmitPqPriceFeed` rollback, `TX_INTRINSIC_GAS`, CLOB `MAX_MATCH_FILLS_PER_ORDER`), WASM (`SubCallSnapshot`, `caller` vs `origin`, `validate_code_hardened`, per-byte `send_message` fuel, `deploy_with_nonce`, `outbound_messages` after `commit_native`, `Eager` consensus cache), PMM (`wUSDT` CEI + `ZeroMint`/`ZeroPayout`), canonical `PQ1` `decode_canonical` (`381/382`, gated off `u64::MAX`).
- [x] **R2 (`abad158cf`)**: Two-level `BlockHeader` v4 + `body_commitment`, fail-closed light-client/CLI/sync verification, `Domain::EvmBindings` (`0B` empty, first-writer-wins), `O(1)` RAM `hydrate_rpc_from_store`, `SnapV4` storage/sync integration (`386/387`, gated off `u64::MAX`).
- [x] **Live Cluster Recovery (`a8d8ca6cb`)**: Deployed across `A/B/C/D` (`3/4` non-fragile quorum at genesis; note: `nodeC` `9865d3...` was later jailed at `#242` due to pre-fix `dht.store` 4s stalls on `a8d8ca6cb`).

### Upcoming & In-Flight Waves

#### Wave 1 (DONE 2026-11-21): Jitter Optimization (`OPT-JITTER-*`) + Эшелон **R3** (PQ Validator Lifecycle & Remote Signer v2)
- [x] `OPT-JITTER-INFNODE`: `Arc<StoredValue>` zero-copy snapshots in `infnode/dht.rs` + 10s throttled `sweep` in `infnode/node.rs` (eliminates 4s `Arc::make_mut` stalls on `dht.store`; `infnode` lib `62/62`, `clippy 0/0`).
- [x] `OPT-JITTER-NET`: `join_with_quorum_or_timeout` (`35ms` straggler grace) in `consensus_net.rs`, `<=120ms` minor-gap `try_catch_up` cap & 4x reduction in redundant `dht.store` publishes in `consensus_driver.rs`.
- [x] `R3-A..E`: `PQ_LIFECYCLE_ACTIVATION_HEIGHT = u64::MAX`, `PqRegistry` PoP/retention `720_000`/explicit `cancel_rotation`, `RemotePqSigner` v2 (`897B`/`666B`), `ValidatorStake::withdrawal_address`, `Domain::PqRegistry`, `ValidatorStakeV1`/`DomainSnapshotV9`, `SnapV4::PqRegistry = 272`, `OpCode 59..=64`, `InMemoryStateEngine::pq_registry`, `sync_committed_pq_registry`, `light_client` height-key.
- [x] `R3-F` + `R3` тесты: `r3_pq_registry_signer_tests` 11/11, `r3_staking_commit_tests` 6/6, `r3_vm_engine_apply_tests` 6/6, `r3_storage_pq_registry_tests` 3/3, `r3_consensus_readers_tests` 3/3, `r3_runtime_node_rpc_cli_tests` 6/6; `pq_rpc_tests` 4/4, `pentest_rpc_surface` 5/5.
- [x] **Полный гейт `stellereum`: `397/397` бинарей зелёные, `clippy --all-targets -D warnings` 0/0** (`docs/OPEN_DEFECTS.md` обновлён; `FORK_ID`/`COMMITMENT_VERSION` не двигались).
- [x] `OPT-PARALLEL-WAVE` (`PlainTxPlan` inline `[;3]` + selective penalty/vesting read + flat `par_iter().with_min_len`). *(Опционально на будущее: `clone_for_simulation_for_payload`, `ReceiptIndex::by_contract_events`.)*

#### Wave 2 (DONE 2026-11-21, активация в R5): Эшелон **R4** — Bridge V2 Release Authorization + W4 Economics, History & Geyser-Lite
- [x] **Phase R4.1** (4 parallel no-cargo workers on disjoint files; все правки вошли в дерево):
  - `R4.1-Bridge`: `bridge.rs`, `bridge_adapters.rs`, `native_api.rs`, `examples/vuln_hunt5.rs` (`BRIDGE_V2_ACTIVATION_HEIGHT = u64::MAX`, `PqKeyLookup`, `BridgeIntent::ReleaseProof` (`8`), `StoredHeader::signing_message_v2`, `AdapterKindTag`, `Challenge` on `DepositProof`, `RETRACTION` precedence, strict EVM pinning, Falcon-512 `MultisigRelayer` in `vuln_hunt5`).
  - `R4.1-W4-E2`: `evm_adapter/*`, `tokenomics.rs`, `staking.rs`, `governance.rs` (`wei_to_nano_exact`, integer `eth_feeHistory`, `mul_div_floor_256` in `GenesisVault`, `pow_half_fixed_exact_q64`, `ValidatorRewardState::accrue` rescale carry, `distribute_fee_reward`, `emission_carry_q64`, optional `GovAction::SetFeeSplitBps`).
  - `R4.1-W4-History`: `storage.rs`, `token.rs`, `contract.rs`, `rpc/{reads,cache}.rs`, `stellereum-indexer` (`"tx_by_addr"`, `"events_by_contract"`, `"receipt_meta_v2"`, cursor pagination for `stell_getAddressHistory`, `stell_getProgramAccounts`, `stell_getTokenAccountsByOwner`, `stell_getEvents`).
  - `R4.1-W4-Geyser`: `rpc/{streams,state}.rs`, `node/consensus_driver.rs` (`self.engine.shard_id()` in `record_block`, `seq` + `GEYSER_REPLAY_WINDOW = 512` + `after_seq` + explicit `Lagged` + `AccountUpdates` / `TokenTransfers` topics).
- [x] **Phase R4.2** (после R4.1; `accrue` rescale-carry и committed `emission_carry_q64` вынесены отдельным пунктом ниже):
  - `R4.2-Commit`: `commitment.rs` (`BRIDGE_V2_RELEASE_V1`, `STAKING_EMISSION_CARRY_V1`, optional `SetFeeSplitBps`, `0B` when empty/zero), `chain_spec.rs` (`BRIDGE_V2_ACTIVATION_HEIGHT`, `FEE_MARKET_V2_ACTIVATION_HEIGHT`, `SUB_NANO_STRICT_ACTIVATION_HEIGHT` all `u64::MAX`).
  - `R4.2-Engine`: `state_engine/{apply,parallel,settlement,accounts,types}.rs`, `svm.rs`, `mempool.rs`, `runtime/{mev_sync,consensus_step}.rs`, `cli/{args,tx_builders}.rs` (Bridge V2 settlement wiring, `FEE_MARKET_V2` priority fee debit + burn/proposer/staking split + `MP04` fee-density ordering, `SUB_NANO_STRICT` EVM/reward wiring).
- [x] **R4 Gate**: `bridge_authorization_p0_regression.rs` **4/4 GREEN**, `H-1/H/H+1` & `parallel == sequential` parity (`propose_select_differential_tests` 3/3, `state_commit_batch_tests` 5/5), full `test_parallel.sh -p stellereum` **397/397 GREEN**.
- [x] **Полное закрытие W4 E1/E2 (`FEE-SUBNANO-EXACT` + тесты W4)**: `accrue_with_rescale`, `emission_carry_q64` (`STAKING_EMISSION_CARRY_V1` + `StakingLedgerV7`/`DomainSnapshotV10`), `w4_priority_fee_tests` **4/4**, `w4_sub_nano_tests` **4/4**.

#### Wave 3 (DONE 2026-11-22): Эшелон **R5** — Ruleset v7 Unified Hard-Fork Activation, RPC Optimizations & `_hq_` Sync Fix
- [x] Switched all 8 Ruleset v7 gates in `chain_spec.rs` / `sharding/block.rs` / `state_engine/mod.rs` / `pq_registry.rs` / `bridge.rs` / `tokenomics.rs` from `u64::MAX` to `0` (`ActiveFromGenesis`; `MAX_BLOCK_TIMESTAMP_DRIFT_MS = 3_600_000`, `EMISSIONCapEXACT_ACTIVATION_HEIGHT = u64::MAX` kept).
- [x] Updated `stellereum/src/protocol.rs`: `CONSENSUS_RULESET_VERSION = 7`, `DOMAIN_SET_VERSION = 4`, appended 9 v7 rules + 9 v7 domains into `FORK_ID = 0x3ae00ebc`; added `docs/RULESET_V7.md`, updated `stellereum-sdk` (`45/45` + `20/20` `node-parity`) and `sdk-js` (`23/23` + `tsc` `0/0`).
- [x] Added non-fork optimizations & live-discovered fixes: `clone_for_simulation_for_tx`/`_for_payload` (`accounts.rs`, `rpc/reads.rs`), `ReceiptIndex::by_contract_events` (`rpc/state.rs`, `rpc/reads.rs`), `_hq_` QC companion republication in `retro_publish_blocks` + `QcMissBackoff` + `fetch_block_qc_probe` (`network.rs`, `node/sync.rs`), and deterministic `seed_genesis_pq_registry` at v7 genesis (`node/bootstrap.rs`).
- [x] Migrated legacy height-0 fixtures cleanly under v7 rules (or RAII pre-v7 overrides for explicit historical-hash/pre-activation tests) without weakening assertions.
- [x] Full workspace gate green: `cargo clippy --offline --all-targets -- -D warnings` `0/0` (`stellereum`, `infnode`, `stellereum-contracts`, `stellereum-indexer`, `stellereum-sdk` + `--features node-parity`), `test_parallel.sh -p stellereum` **399/399**, `infnode` `62/62` + `infmail` `28/28` + all 17 integration binaries, `stellereum-indexer` `26/26`, `stellereum-sdk` `45+20+3+1`, `sdk-js` `23/23`, Stage 0 fake-code scan clean, zero `OPEN` items in `docs/OPEN_DEFECTS.md`.

#### Wave 4 (DONE 2026-11-22): Live Cluster Rollout (`A/B/C/D`), Indexer & Site Deploy
- [x] Built & deployed release `stellereum` (`3a2c2ef3e`, `FORK_ID = 0x3ae00ebc`, `CONSENSUS_RULESET_VERSION = 7`, `OPT-JITTER-*`, `_hq_` QC + backoff, `seed_genesis_pq_registry`) across all 4 validators (`A, B, C, D`) with aligned `env.A/B/C/D` (`STELL_MIN_BLOCK_MS=400`, `STELL_CATCHUP_INTERVAL_MS=30000`, `STELL_CATCHUP_BUDGET_MS=500`), clean v7 genesis, and `2000 STELL` self-bond per validator (`total_power = 8000 STELL`, `quorum = 5334 STELL`, **`4/4` active, `fragile: false`**).
- [x] Verified live stability via `scripts/cluster_liveness.sh` (`LIVENESS_RESULT=OK`, `163.00 blk/min`, `spread=0`, `stalled_for=1s`, zero `fetch_block_qc` / `dht.store` 4s stalls) and `stell-loadtest --allow-live --senders 256 --print-all-senders` + `--dry-run`. *(Ongoing 24h soak & optional `UP-5` `stellereum-upgrader` remain ops/follow-up.)*
- [x] Deployed release `stellereum-indexer` (`W4` keyset + SSE) to `nodeA` (`lag=0, synced=true`) and updated `stellereum/site/assets/js/metrics.js` (`e4fbe2ba...`) to `/var/www/stellereum/assets/js/metrics.js`.

#### Deferred Post-Mainnet (`SEPARATE SYSTEM`, out of W0–W5 / R1–R5 scope)
- [ ] `stell-wallet/` full UX + own connect protocol (then WalletConnect v2; MetaMask bridge stays maintenance-only).
- [ ] `explorer-site/` UI & `events-race` completion.
- [ ] L2 / Data Availability, dynamic TON-like shard split/merge (`>2` shards), true ZK prover/verifier for zkML, EVM smart-contract interpreter, second independent consensus client.
