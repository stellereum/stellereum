# Stellereum Completeness Gap Analysis

**Date:** 2026-11-18
**Tree:** `/home/imm/stellereum-project`. Analysis began on `be52ce87c`; the in-progress wave was committed as `f1b10b263` ("Waves 3-4 + test-speed work") while the document was being written. Line references are against `be52ce87c` unless explicitly marked **[f1b10b263]**; §11.1 lists the deltas that commit introduced. This is deliberate: the tree moved under the analysis, and a fixed commit is the only reproducible anchor.
**Scope:** what Stellereum still lacks to be a complete L1, benchmarked against Ethereum/Solana/TON-class expectations.
**Method:** read-only source inspection. Every Stellereum claim below is anchored to `file:line` in this tree or to a pasted `rg` count. No live host was probed, and the test suite was not run (a gate run was in progress). Anything not verifiable from the tree is marked **UNVERIFIED** and listed in §11.

Baseline counts from this tree:

| Measure | Count | Command |
|---|---:|---|
| Rust source files (whole repo, excluding all `target` dirs) | 639 | `find . -name '*.rs' -not -path '*/target/*' \| wc -l` |
| `stellereum/src` lines | 206,287 | `find stellereum/src -name '*.rs' \| xargs wc -l \| tail -1` |
| `stellereum/tests` lines | 172,360 | `find stellereum/tests -name '*.rs' \| xargs wc -l \| tail -1` |
| Integration test files (core crate) | 324 | `ls stellereum/tests \| wc -l` |
| Test attributes (core crate src + tests) | 3,924 | `rg -c '^\s*#\[(tokio::)?test\]' stellereum/src stellereum/tests` summed |
| `cargo-fuzz` targets | 7 | `ls stellereum/fuzz/fuzz_targets \| wc -l` |
| Registry metric constants | 33 | `rg -c 'pub const [A-Z0-9_]+: &str = "stell_' stellereum/src/metrics.rs` |
| Extra ad-hoc gauges (`stell_ready`, 4 `stellereum_*`) | 5 | `rg -oN '# TYPE (stell_[a-z_]+\|stellereum_[a-z_]+)' stellereum/src/explorer.rs` |
| `stell_*` RPC method strings (excluding tests) | 106 | `rg -oN '"(stell_[A-Za-z0-9_]+)"' stellereum/src/rpc --glob '!tests.rs' stellereum/src/native_api.rs \| sort -u \| wc -l` |
| `eth_*` method strings | 32 | `rg -oN '"(eth_[A-Za-z0-9_]+)"' stellereum/src/rpc \| sort -u \| wc -l` |
| Activation constants pinned at `u64::MAX` | 9 at `be52ce87c`, 10 at `f1b10b263` | `rg -n "ACTIVATION_HEIGHT: u64 = u64::MAX" stellereum/src \| wc -l` |
| Hosted CI workflow directories | 0 | `ls .github` → no such directory |

The system is large and unusually well tested for its age (3,924 test attributes, extensive adversarial suites). The gaps below are therefore mostly **activation, productization, and lifecycle** gaps, not "the code is empty" gaps.

---

## 1. Executive summary — the 10 biggest gaps, ranked by what blocks mainnet

### 1. On-chain governance now works on N>1; only binary execution is still gated

Block-carried governance is **active from genesis** (`GOV_OPS_ACTIVATION_HEIGHT = 0`, `stellereum/src/governance.rs:151`). Signed `SysCallGovPropose` / `SysCallGovVote` transactions are applied by a deterministic block scan (`apply_gov_ops`, `stellereum/src/state_engine/apply.rs`), and a deterministic sweep finalizes due proposals and executes every matured `GovAction` of all 13 types in ascending id order (`apply_governance_transition`). The RPC `stell_submitProposal` / `stell_vote` `tx` form admits those signed payloads on every node; the legacy direct-parameter form is solo-only (`validator_set.len() > 1` refuses) and `STELL_GOV_ALLOW_MULTINODE_WRITES=1` remains a documented fork switch.

Remaining gap: `SoftwareUpgrade` / `CancelUpgrade` execution is filtered out unless `UPGRADE_EXEC_ACTIVATION_HEIGHT` (`stellereum/src/governance.rs:80`) is also open, and that constant is still `u64::MAX`. A passed upgrade proposal therefore finalizes, matures, and then stays `Passed` without installing `AppliedParams::upgrade_plan`. This is now a **targeted upgrade-execution gap**, not a governance gap: ratifying the second gate (and adding it to `chain_spec`) is the remaining work.

### 2. No protocol version, no state-schema version, and no migration framework

`Block` has no version field: its fields are shard id, height, prev hash, state root, transactions, cross-shard messages, timestamp, proposer, signatures, QC, shard headers, order root, epoch-key commitment, MMR epoch root, CN-VRF payload, last QC (`stellereum/src/sharding/block.rs:257-390`). Chain identity is mixed into the block hash (`stellereum/src/sharding/block.rs:812-824`), but the *rules version* is not. The only versioning present is a state-digest constant, `COMMITMENT_VERSION = 5` (`stellereum/src/commitment.rs:100`), whose own comment says every data directory needs a wipe when it changes (`stellereum/src/commitment.rs:97-100`), and a P2P frame version (`FRAME_VERSION = 2`, `infnode/crates/infnode/src/proto.rs:135-137`) that does not encode consensus rules.

Upgrades are a single `UpgradePlan { name, height, sha256 }` (`stellereum/src/governance.rs:593-599`); as of `f1b10b263` the plan is also committed into the governance digest (`stellereum/src/commitment.rs:784-788`, **[f1b10b263]**), so two nodes that disagree about the plan now disagree about the root. The halt predicate is `plan.height <= height` rather than exact equality (`stellereum/src/node/consensus_driver.rs:2895`, **[f1b10b263]**), the halt drains the persistence queue before exiting (`:2928`), and a durable marker plus startup guard refuses consensus until the upgraded binary proves the plan (`stellereum/src/node/upgrade_halt.rs:338-407`, `stellereum/src/node/bootstrap.rs:940-966`, **[f1b10b263]**). That closes the silent-straggler hole for a node that finalizes late or restarts after the halt.

What remains: no expiry, no `from_version`/`to_version` fields (the plan `name` doubles as a target-version label), no queued plans, and no per-version migration hook. Backward compatibility is instead a hand-maintained chain of legacy snapshot decoders (`stellereum/src/storage.rs:2554-2640`), which works for additive fields but is not a migration system. **Blocks safe mainnet upgrades.**

### 3. The differentiating protocol is compiled but switched off

Three protocol capabilities are now **active from genesis**: `COMPACT_GOSSIP_ACTIVATION_HEIGHT = 0` (`stellereum/src/consensus_net.rs:2097`), `XPC_ACTIVATION_HEIGHT = 0` (`stellereum/src/xshard2pc.rs:146`) and `GOV_OPS_ACTIVATION_HEIGHT = 0` (`stellereum/src/governance.rs:151`). The remaining `u64::MAX` gates are:

- `QC_SPLIT_ACTIVATION_HEIGHT` (`stellereum/src/consensus/sortition.rs:179`)
- `BEACON_DRAW_ACTIVATION_HEIGHT` (`stellereum/src/consensus/sortition.rs:539`)
- `CNVRF_V3_ACTIVATION_HEIGHT` (`stellereum/src/consensus/sortition.rs:650`)
- `EMISSIONCapEXACT_ACTIVATION_HEIGHT` (`stellereum/src/tokenomics.rs:55`)
- `MEV_RESHARE_ACTIVATION_HEIGHT` (`stellereum/src/mev_epoch.rs:1703`)
- `SPRT_TIER3_ACTIVATION_HEIGHT` (`stellereum/src/oracle.rs:205`)
- `UPGRADE_EXEC_ACTIVATION_HEIGHT` (`stellereum/src/governance.rs:80`)
- `CHAIN_BINDING_ACTIVATION_HEIGHT` (`stellereum/src/chain_binding.rs:48`, explicit never sentinel)
- `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` (`stellereum/src/zkml_attestation.rs:144`)

The public schedule still tracks only 7 gates (`stellereum/src/chain_spec.rs:130-180`) — QC split, beacon draw, CN-VRF v3, compact gossip, emission, PQ transport, XPC — and `PQ_TRANSPORT_H_ACTIVATION_HEIGHT = 10_000` is explicitly "retained only for the frozen schedule" (it no longer selects a transport). `GOV_OPS`, `UPGRADE_EXEC`, `MEV_RESHARE`, `SPRT_TIER3`, `CHAIN_BINDING` and `ZKML_CONTEXT_BINDING` are absent from the operator-visible schedule. **The core completeness gap is now narrower: the roadmap's remaining off-by-default paths are the randomness/aggregation/emission upgrades and binary execution, not governance or 2PC.**

### 4. Validator lifecycle dead-ends: no unjail, no commission change, no client-visible redelegation

`StakingLedger::unjail` exists (`stellereum/src/staking.rs:1464`), but `rg -n "unjail\(" stellereum/src` returns exactly **one** hit: the definition. There is no opcode, no RPC arm, no wallet command. Jail is installed automatically on downtime (`stellereum/src/staking.rs:3315-3338`) and only `unjail` removes it (`stellereum/src/staking.rs:1482`), so a jailed validator is permanently out of the set.

The bounded commission-change path exists in the ledger (`announce_commission` at `stellereum/src/staking.rs:1529`, `apply_commission` at `:1599`), but `rg -n "announce_commission\(|apply_commission\(" stellereum/src` returns exactly the **two definitions** — no callers. Commission is fixed at bond time; the wallet says so explicitly (`stell-wallet/src/main.rs:178-181`). `redelegate` likewise has a ledger implementation (`stellereum/src/staking.rs:1982`) and **no** opcode/RPC/wallet path (`rg -n "fn redelegate\(" stellereum/src` → 1 hit, the definition).

Consequence: validators cannot recover from an outage, cannot reprice, and cannot move delegated stake without unbond/rebond. **Blocks a functioning validator market.**

### 5. No EVM execution; EVM value transfers need a PQ binding + carrier

The EVM adapter is a JSON-RPC translation layer, not an EVM. `eth_call` only answers read-only native-token views and returns `0x` for any address with no committed code or any state-changing selector; it never executes Solidity (`stellereum/src/evm_adapter/adapter.rs:673-810`). `eth_getCode` serves committed bytecode or `0x`, and `eth_getStorageAt` has no EVM trie to read.

The write path is honest but two-part: a 20-byte EVM address must be **bound** to a 32-byte PQ account by a Falcon-signed `SysCallBindEvmAddress` statement, and an EVM intent then settles only as a normal PQ1 **carrier** transaction whose `SysCallEvmCarrier` payload carries the EIP-155/1559 bytes, the bound Falcon key and its signature over `keccak256(evm_tx)`. Value transfers (empty calldata, an existing recipient, value > 0) are supported; contract creation and calldata are refused with `evm-contract-execution-unsupported` because there is no EVM interpreter or EVM state trie. The binding index is a node-local routing/replay index, **not** part of the state root: consensus re-checks the pure signatures at execution, so a stale index can change admission/routing but never move different money (`stellereum/src/evm_adapter/binding.rs:1-80`, `stellereum/src/state_engine/accounts.rs:2580-2635`).

The chain advertises Ethereum chain id 5757 (`stellereum/src/zkml.rs`), so MetaMask can read balances/nonces and submit a bound value transfer once the PQ wallet supplies the carrier signatures, but it cannot deploy or call Solidity. **Still an ecosystem gap; no longer a misleading dead write path.**

### 6. Economics are not mainnet-grade: genesis premine sits outside the cap, and the fee model is fixed

The global cap is enforced on post-genesis mints (`TOTAL_SUPPLY_CAP = 1e18` nano = 1e9 STELL, `stellereum/src/tokenomics.rs:27`; counter reserved before credit at `stellereum/src/state_engine/accounts.rs:1761-1790`; folded into the root at `stellereum/src/state_engine/accounts.rs:882-900`). But genesis credits every validator 100M STELL by direct account write (`stellereum/src/node/policy.rs:358`, `stellereum/src/runtime/lanes.rs:13-18`), bypassing the mint counter, with no assertion that `N × 100M + faucet ≤ 1B`. `TokenAllocation` (250M/150M/350M/150M/100M, `stellereum/src/tokenomics.rs:67-73`) is never instantiated on the live path (`rg -n "TokenAllocation" stellereum/src` → the type definition, its `Default` impl, and two doc comments only).

Live emission is the flat 0.317 STELL per block to the proposer (`stellereum/src/tokenomics.rs:38`, `:320-330`); the cap-exact geometric schedule is off (`:51`). Fees are the **declared** `gas_limit`, not gas used, for every block application (`stellereum/src/state_engine/apply.rs:1796-1808`, `:1892`), so users overpay for unused gas. There is no dynamic base fee and no burn; `base_fee` is the governance-set admission floor (`stellereum/src/mempool.rs:566-570`, `stellereum/src/node/bootstrap.rs:209`). **Blocks credible tokenomics.**

### 7. Sharding: 2PC is live from genesis, but no shard split has ever run

`XPC_ACTIVATION_HEIGHT = 0` (`stellereum/src/xshard2pc.rs:146`): every new cross-shard transfer uses PREPARE → PREPARE-ACK → COMMIT, the target credits only a proven COMMIT, and the two-shard soak (`scripts/soak_two_shard.sh`, `docs/TWO_SHARD_DEPLOY.md`) exercises real processes. `STELL_XPC_ACTIVATION_HEIGHT` is deprecated and ignored. What remains is topology work, not the value protocol: the shipped configuration is the fixed `{0,1}` pair, binding beyond shard 0 requires an explicit experimental hatch (`stellereum/src/node/bootstrap.rs`), and the split/merge state machine and trie migration (`stellereum/src/sharding/topology.rs:539-631`) are demonstrated only over synthetic state ("no split has ever been performed on a live network"). **Blocks a live scalability story beyond the two-shard pair.**

### 8. No external human audit, no real bug bounty, no hosted CI

The only third-party-shaped audit in tree is a static AI review that explicitly says it did **not** include dynamic fuzzing, external crypto audit, or a live-network pentest (`docs/audits/NEURAL_AUDIT_2026-11-04.md:5`). `SECURITY.md` is still a draft with placeholders (`SECURITY.md:1-7`, `:35-37`). There is no `.github` directory at all; the nightly gate is a manually installed cron job (`scripts/nightly_gate.sh:3-5`, `scripts/nightly_ci_notes.md:1-9`). **Blocks mainnet risk acceptance.**

### 9. Validator key custody has no HSM path for the consensus key

Node keys are encrypted at rest with Argon2id + XChaCha20-Poly1305 and 0600 permissions (`stellereum/src/node_keys.rs:1-18`), which is good. But the remote-signer interface is Ed25519-only; the code documents an explicit "HSM GAP" because the Falcon-512 vote key still comes from a local file (`stellereum/src/remote_signer.rs:880`, `stellereum/docs/OPERATIONS.md:1343-1348`). There is no PKCS#11/KMS integration for Falcon (`rg -ni "pkcs11|hsm|yubikey" stellereum/src stell-wallet/src` → the only hits are doc comments and the HSM-gap note). **Blocks institutional validators.**

### 10. Client/developer surface is a Rust-only transaction builder and loopback services

`stellereum-sdk` is a five-shape tx builder (`stellereum-sdk/src/lib.rs:1-20`), installed from git (`stellereum-sdk/README.md:29-33`); there is no JS/TS/Python RPC SDK. The wallet is a CLI (`stell-wallet/src/main.rs:70-120`), the explorer and RPC default to loopback (`stellereum/src/node/bootstrap.rs:1260`, `:1288`), and no public endpoint is published in-tree. Contracts are WAT/WASM with "upgrade = redeploy" and no proxy standard (`docs/site/03-contracts.md:55`). **Blocks ecosystem onboarding.**

---

## 2. Protocol upgrade & release engineering

### 2.1 What exists

- A read-only, compile-time activation schedule with 7 named gates (`stellereum/src/chain_spec.rs:117-165`), including an `ActivationStatus` enum and `is_active_at` (`stellereum/src/chain_spec.rs:16-70`).
- Height-gated constants for QC split, beacon draw, CN-VRF v3, compact gossip, cap-exact emission, PQ transport, XPC and governance (`stellereum/src/consensus/sortition.rs:179`, `:539`, `:650`; `stellereum/src/consensus_net.rs:2097`; `stellereum/src/tokenomics.rs:55`; `stellereum/src/mev_epoch.rs:995`; `stellereum/src/xshard2pc.rs:146`; `stellereum/src/governance.rs:80,151`).
- On-chain `SoftwareUpgrade { name, height, sha256 }` and `CancelUpgrade` actions (`stellereum/src/governance.rs:208-214`), stored as a single `UpgradePlan` (`stellereum/src/governance.rs:593-599`).
- Path-traversal hardening: name must be one safe segment (`stellereum/src/governance.rs:607-645`), candidates are resolved under `data/upgrades/` (`:729-737`), the binary is hash-verified and staged before exec (TOCTOU closed) at `:751-790`.
- Halt semantics: at the plan height the node snapshots state, then exits with code 42 for a supervisor to restart (`stellereum/src/node/consensus_driver.rs:2975`); live `execve` is opt-in via `STELL_AUTO_UPGRADE=1` (`stellereum/src/governance.rs:676-720`).
- Fail-loud halt on unprovable state: `process::exit(1)` (`stellereum/src/node/consensus_driver.rs:466`, `:626`).
- Operator runbooks for upgrade, rollback and state-compat checks (`stellereum/docs/OPERATIONS.md:1540-1660`) and a documented "no automatic downgrade" rule (`:1573`).
- Build identity exposed in `/metrics` and `/api/version` (`stellereum/src/metrics.rs:1274-1310`, `stellereum/src/explorer.rs:2091-2160`).
- A dedicated upgrade/recovery analysis with a gate inventory, mixed-version matrix and recovery-time bounds (`docs/UPGRADE_AND_RECOVERY.md:1-60`, `:83-94`, `:241-253`, `:397-405`).

This is more release engineering than most young chains have. The gaps are structural, not cosmetic.

### 2.2 What is missing

1. **No consensus-rules version anywhere.** Not in `Block` (`stellereum/src/sharding/block.rs:257-390`), not in the P2P handshake beyond a frame version (`infnode/crates/infnode/src/proto.rs:135-137`), and not in a persisted protocol/schema key: the only chain-identity meta key is `genesis_state_root` (`stellereum/src/node/bootstrap.rs:169-177`, `:884-904`), alongside the consensus checkpoint (`stellereum/src/storage.rs:947`). A mixed-binary network is not detected at the handshake; it fails closed by stalling or isolating peers, not by telling the operator "wrong version". The upgrade doc's mixed-version matrix records this (`docs/UPGRADE_AND_RECOVERY.md:243-253`), and the CN-VRF rollout doc shows a sortition change makes the old binary compute different proposers for the same height (`docs/CNVRF_V3_ROLLOUT.md:96`).
2. **No fork-id / network-magic handshake.** Mature chains reject peers on a different fork/feature set at handshake time. Here the handshake validates PQ identity and frame version only (`infnode/crates/infnode/src/proto.rs:318-437`).
3. **No general state migration.** Legacy decoders exist for `DomainSnapshotV1..V7` (`stellereum/src/storage.rs:2554-2640`), but there is no `migrate(from_version, to_version)` hook executed at an activation height, and no forward-compat guard that refuses a newer schema. A `COMMITMENT_VERSION` bump still means a wipe (`stellereum/src/commitment.rs:97-100`).
4. **Upgrade scheduling is still single-shot, and the binary-execution leg is gated.** The `f1b10b263` wave replaced exact equality with `plan.height <= height` and added a drain plus a durable halt marker/startup guard (`stellereum/src/node/consensus_driver.rs:3129-3200`; `stellereum/src/node/upgrade_halt.rs:338-407`), so a node that finalizes late halts loudly instead of running the old rules. The plan is committed (`commitment.rs:784`), and the deterministic sweep executes every non-upgrade `GovAction`. What remains: no expiry, no `from_version`/`to_version` contract, no queued plans, and `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX` (`stellereum/src/governance.rs:80`), so a passed `SoftwareUpgrade` never matures into `upgrade_plan`.
5. **One plan at a time, last write wins.** `upgrade_plan: Option<UpgradePlan>` (`stellereum/src/governance.rs:899`) supports no queue, no staging window, no per-version migration metadata.
6. **No rollback automation.** Rollback is a documented manual sequence (`stellereum/docs/OPERATIONS.md:1627-1650`); there is no on-chain "abort upgrade" that survives a half-upgraded network.
7. **No release provenance.** Binaries are hash-checked at exec, but the plan carries only `name`, `height` and `sha256` — no publisher key, no signature, no build attestation (`stellereum/src/governance.rs:593-599`).
8. **The schedule is incomplete.** `chain_spec` tracks 7 gates; `GOV_OPS_ACTIVATION_HEIGHT`, `UPGRADE_EXEC_ACTIVATION_HEIGHT`, `SPRT_TIER3_ACTIVATION_HEIGHT`, `MEV_RESHARE_ACTIVATION_HEIGHT`, `CHAIN_BINDING_ACTIVATION_HEIGHT` and `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` are absent (`rg -n "GOV_OPS|SPRT|RESHARE|UPGRADE_EXEC|CHAIN_BINDING|ZKML_CONTEXT" stellereum/src/chain_spec.rs` → 0).
9. **No RPC to inspect the schedule or protocol version.** There is no `stell_chainSpec`, `stell_version`, or equivalent in the 106 `stell_*` methods; only HTTP `/api/version` (`stellereum/src/explorer.rs:2091`).

### 2.3 Minimal work to close

- **P0:** Add `protocol_version: u16` to `Block` as an appended, `serde(default)` field, mix it into the hash only when non-zero (the existing pattern for `order_merkle_root` and `shard_headers`), reject proposals/votes with a mismatched version, and echo it in the P2P handshake as a fork-id. Owner: `stellereum/src/sharding/block.rs`, `stellereum/src/consensus/types.rs`, `infnode/crates/infnode/src/proto.rs`.
- **P0:** Add `state_schema_version` to storage meta and a `migrations: &[(u32, fn)]` registry executed once at startup and at the upgrade height; refuse an unknown newer version. Owner: `stellereum/src/storage.rs`, `stellereum/src/node/bootstrap.rs`.
- **P0:** Ratify and enable the upgrade-execution sweep (`UPGRADE_EXEC_ACTIVATION_HEIGHT`), then add `created_at`/`expires_at`, a structured `from_version`/`to_version`, and a queued-plan list. The late-halt predicate and durable marker already exist as of `f1b10b263` (`stellereum/src/node/consensus_driver.rs:2895`; `stellereum/src/node/upgrade_halt.rs:338-407`). Owner: `stellereum/src/governance.rs`, `stellereum/src/state_engine/apply.rs`, `stellereum/src/node/consensus_driver.rs`.
- **P1:** Add `stell_chainSpec` and `stell_version` RPCs returning `chain_spec::current_activation_schedule().summary_lines()` and the build hash. Owner: `stellereum/src/rpc/reads.rs`.
- **P1:** Sign release artifacts and include a publisher key in `UpgradePlan`. Owner: `stellereum/src/governance.rs`, `scripts/`.

---

## 3. Node operations

### 3.1 What exists

- **Metrics and health.** 33 registry constants plus 5 ad-hoc gauges (`stellereum/src/metrics.rs:68-151`, `stellereum/src/explorer.rs:2016-2028`). HTTP surface: `/health`, `/healthz`, `/readyz`, `/metrics`, `/api/version` (`stellereum/src/explorer.rs:2204-2209`). `/readyz` returns 503 with named failure reasons (`stellereum/src/explorer.rs:1932-1950`).
- **Alerting.** 15 Prometheus rules in `ops/alert_rules.yaml` and 8 in `stellereum/scripts/monitor/alerts.rules`; provenance is documented (`ops/alert_rules.yaml:1-26`).
- **Graceful shutdown.** SIGTERM/SIGINT handler drains the persistence queue with a 240 s cap inside systemd's 300 s stop budget (`stellereum/src/node/bootstrap.rs:918-955`; helper at `stellereum/src/storage.rs:3541-3643`). Mempool is saved on shutdown (`stellereum/src/node/bootstrap.rs:1160-1185`).
- **systemd.** Four node units with restart limits, `MemoryMax`, `CPUQuota`, journald output (`stellereum/scripts/systemd/stell-nodeA.service:1-45`), plus indexer and prune units (`scripts/systemd/stellereum-indexer.service`, `scripts/systemd/stell-node-prune.timer`).
- **Logs.** journald drop-in caps 500M/7 days (`scripts/systemd/journald-stellereum.conf:1-8`); logrotate config for stand logs (`stellereum/scripts/logrotate.stellereum:1-12`).
- **Backups.** Off-host 3-2-1 script (`scripts/backup_offhost.sh`), verify (`scripts/backup_verify.sh:1-15`), non-destructive restore drill (`scripts/backup_restore_drill.sh:1-20`), and a runbook (`ops/backup_runbook.md:1-30`).
- **Pruning/archival.** Retention policy in storage (`stellereum/src/storage.rs:238-284`): archive by default, prune mode via `STELL_ARCHIVE=0/false`, `STELL_KEEP_BLOCKS` default 50,000. Prunes bodies, receipts, state snapshots and every auxiliary domain (`stellereum/src/storage.rs:822-1105`), with a bounded batch (`:355-360`). Snapshot cadence is 1,000 blocks by default, minimum 50 (`stellereum/src/node/policy.rs:246-252`), with an adaptive skip gate (`stellereum/src/snapshot_cadence.rs:1-20`).
- **Disk growth observability.** `stell_data_dir_bytes` and `stell_snapshot_count` are exported (`stellereum/src/metrics.rs` constants list), and a prune cron script exists (`scripts/node-prune-cron.sh`).
- **Liveness alarm.** A validator that consumes no consensus traffic for 5 minutes screams on stderr (`stellereum/src/liveness_alarm.rs:1-30`).
- **Hot-path timing.** Each consensus tick logs `[perf] tick ...` and an aggregate `[perf][tick-split]` line with catch-up/retro/probe/join timings (`stellereum/src/node/consensus_driver.rs:3859`, `:3882`). These are logs, not exported metrics, so they cannot be alerted on.

### 3.2 What is missing

1. **Observability is thin for operators.** No peer-count gauge (documented gap in `stellereum/scripts/monitor/alerts.rules:24-28`), no RPC latency/error histogram, no P2P bandwidth/queue depth, no per-validator signing/uptime metric, no upgrade/activation metric, no finality-latency histogram. 38 series is roughly one order of magnitude below mature node exporters.
2. **No alert delivery.** Prometheus rules exist, but there is no Alertmanager config, no PagerDuty/Slack route, and no on-call escalation (`find . -iname '*alertmanager*'` → 0).
3. **No dashboards.** No Grafana JSON and no status-page generator (`find . \( -iname '*grafana*' -o -iname '*dashboard*' \) -not -path '*/node_modules/*' -not -path '*/target/*'` → 0). `ops/status_page.md` is prose.
4. **No tracing/OTel.** `rg "opentelemetry" stellereum` → 0. Logs are stderr/journal only.
5. **Node units are stand-specific, not a product.** The units hard-code `/root/nodeA..D`, ports and paths (`stellereum/scripts/systemd/stell-nodeA.service:13-18`). There is no templated `stell-node@.service`, no Ansible/Helm/Terraform, no multi-region recipe (`find . \( -iname '*.tf' -o -iname 'Chart.yaml' -o -iname 'helmfile*' \) -not -path '*/node_modules/*' -not -path '*/target/*'` → 0).
6. **Backup is manual off-host.** The upload target is refused until an uploader is configured (`ops/backup_runbook.md:15-19`); there is no scheduled backup, no retention automation, and no CI-run restore drill.
7. **No disk watermark action.** Disk usage is a gauge and an alert, but there is no automatic prune/stop at a threshold; the operator must run the cron/timer.
8. **CI is absent.** No hosted pipeline (`.github` absent; `scripts/nightly_ci_notes.md:1-9`). The 5-stage nightly gate is manual cron (`scripts/nightly_gate.sh:3-5`).
9. **Log shipping is absent.** No Fluent Bit/Vector/Loki/Filebeat config (`rg -ni "fluent|vector\\.toml|loki|filebeat" ops scripts stellereum/scripts` → 0); journald is local-only.
10. **Snapshot/restore is not version-aware.** A restore does not check protocol/schema version before boot; it relies on decoders and the genesis-root guard (`stellereum/src/node/bootstrap.rs:884-904`).

### 3.3 Minimal work to close

- Add `stell_peer_count`, `stell_rpc_requests_total{method,code}`, `stell_rpc_latency_seconds`, `stell_validator_signed_heads_total`, `stell_finality_latency_seconds` to `stellereum/src/metrics.rs` and increment them in `stellereum/src/rpc/mod.rs` / `stellereum/src/node/consensus_driver.rs`.
- Add one Grafana dashboard JSON and an Alertmanager route under `ops/`.
- Add a templated `stell-node@.service` plus a Compose/Ansible example; keep the stand units as examples.
- Add a weekly `backup_restore_drill.sh` timer and a CI job that runs it against a fixture.
- Add `STELL_MIN_FREE_DISK_BYTES` with a fail-loud refusal to start/finalize below it.

---

## 4. Client surface

### 4.1 What exists

- **RPC breadth.** 106 distinct `stell_*` method strings and 32 `eth_*` methods (counts above). The `stell_*` surface covers chain/block/tx reads, balances, staking, delegation, governance, bridge, oracle, order book, tokens, contracts, sessions, proofs, PQ registry, MEV, and sharding (`rg` list at `stellereum/src/rpc/reads.rs`, `writes.rs`, `contracts.rs`, `stellereum/src/native_api.rs`).
- **Ethereum RPC coverage.** Present: 32 `eth_*` methods plus `net_*`/`web3_*`, including `eth_chainId`, `net_version`, `web3_clientVersion`, `net_listening`, `net_peerCount`, `eth_syncing`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_estimateGas`, `eth_feeHistory`, `eth_getCode`, `eth_getBalance`, `eth_getTransactionCount`, `eth_blockNumber`, `eth_getBlockBy{Number,Hash}`, `eth_getTransactionReceipt`, `eth_getTransactionByHash`, block tx-count methods, tx-by-index methods, uncle methods, `eth_call`, the filter lifecycle, `eth_getLogs`, `eth_getStorageAt`, `eth_sendRawTransaction` (`stellereum/src/rpc/eth.rs:617-797`). Absent (verified 0 hits): `eth_subscribe`, `eth_unsubscribe`, `eth_getProof`, `eth_accounts`, `eth_sendTransaction`, `eth_signTransaction`, `eth_getBlockReceipts`, `eth_protocolVersion`, `eth_coinbase`, `eth_mining`, `eth_hashrate`, `eth_createAccessList` (`rg -n "eth_subscribe|eth_getProof|eth_accounts|eth_sendTransaction|eth_signTransaction|eth_getBlockReceipts|eth_protocolVersion|eth_coinbase|eth_mining|eth_hashrate|eth_createAccessList" stellereum/src` → 0).
- **Subscriptions.** WebSocket at `/ws` (`stellereum/src/rpc/streams.rs:1652`) and SSE; topics are `newHeads`, `newTxs`, `events`/`logs`, and `invalidations` (`stellereum/src/rpc/streams.rs:48-70`, `:601-604`). Caps: 4,096 global, 64 per client (`:21`, `:30`).
- **Proofs and light client.** `stell_getProof` returns an account inclusion/exclusion proof plus optional storage-key proofs (`stellereum/src/rpc/reads.rs:566-700`), `stell_getArchiveProof` serves historical keys, `stell_getHistoricalRoot` serves the certified root (`:1451-1459`), and the external `light-client` CLI anchors proofs to an out-of-band validator set and a quorum certificate (`stellereum/src/light_client_cli.rs:1-40`).
- **Rate limiting and bounds.** Per-IP fixed window default 30 req/s (`stellereum/src/explorer.rs:27-37`); 1 MiB RPC body cap (`stellereum/src/rpc/state.rs:12`); separate budget for expensive `stell_estimateFee` (`stellereum/src/rpc/reads.rs:2360-2378`); subscription caps.
- **Pagination.** `limit`/`offset` on token lists (`stellereum/src/rpc/reads.rs:1827-1845`), `limit` on events and block feeds (`:2020-2040`, `:2598-2608`).
- **Error semantics.** JSON-RPC 2.0 codes with human-readable messages; distribution: 138×`-32602`, 57×`-32000`, 20×`-32004`, 16×`-32001`, 14×`-32600`, 7×`-32601` (`rg -oN '\-32[0-9]{3}' stellereum/src/rpc/*.rs`).
- **SDK and wallet.** Rust tx-builder SDK (`stellereum-sdk/src/lib.rs:1-20`) with chain-bound envelopes, PQ signing and `stell_estimateFee`/`stell_sendRawTransaction` helpers. Wallet CLI with 45 top-level commands plus subcommands, including staking, delegation, tokens, sessions, PMM, order book and SPV balance checks (`stell-wallet/src/main.rs:70-120`, `:128-270`).
- **Explorer and indexer.** 12 explorer API routes plus server-rendered HTML (`stellereum/src/explorer.rs:2204-2225`); SQLite indexer with blocks/txs/accounts/events/verified sources (`stellereum-indexer/src/db.rs:308-403`) and 44 REST routes (`stellereum-indexer/src/server.rs:131-186`).
- **Faucet.** Opt-in, PQ-signed, hourly per-IP and lifetime per-address caps, optional Turnstile (`stellereum/src/node/bootstrap.rs:1081-1090`, `stellereum/src/rpc/faucet.rs:61-70`, `:371-380`).

### 4.2 What is missing

1. **No Ethereum-compatible subscriptions.** `rg -c "eth_subscribe|eth_unsubscribe" stellereum/src` → **0**. Tools that expect `eth_subscribe` cannot use the WS endpoint.
2. **No `eth_getProof`.** The proof engine exists but is exposed only as `stell_getProof` (`rg -l "eth_accounts|eth_signTransaction|eth_sendTransaction|eth_getProof" stellereum/src` → **0 files**).
3. **No standard Ethereum write methods.** `eth_accounts`, `eth_sendTransaction`, `eth_signTransaction` are absent (same `rg` → 0). MetaMask can only use `eth_sendRawTransaction` for a transfer-shaped intent (`stellereum/src/evm_adapter/tx.rs:9-24`), not contract deployment.
4. **Fake or decorative fields returned as live data.** `net_peerCount` = `"0x2"` (`stellereum/src/evm_adapter/types.rs:69`), `eth_gasPrice`/`eth_maxPriorityFeePerGas`/`eth_feeHistory` are constants derived from no fee market (`stellereum/src/mempool.rs:566-569`), `eth_getCode` is always `0x` (`stellereum/src/evm_adapter/adapter.rs:2174`). This is worse than a missing method because it silently lies.
5. **No schema contract.** No OpenAPI document and no machine-readable JSON-RPC schema (`rg -ni "openapi|swagger|json-schema" stellereum/docs docs/specs` → 0). Client code must be written by hand against prose (`stellereum/docs/RPC.md`, 2,986 lines).
6. **No cursor pagination.** Only `limit`/`offset` and capped scans; no stable cursor for events or blocks (`rg -n "cursor" stellereum/src/rpc` → 0).
7. **No general-purpose SDK.** Rust only; no TypeScript/JavaScript, Python, Go or Java client. The only TS artefact is contract-stub codegen (`stellereum/src/bin/abi_codegen.rs:1-20`), not an RPC client.
8. **Wallet is CLI-only.** No browser extension, mobile wallet, or hardware-wallet integration (`rg -ni "ledger|trezor|yubikey|hwi" stell-wallet/Cargo.toml stellereum/Cargo.toml` → 0 dependencies; the only `ledger` hits in `stell-wallet/src` are accounting terms).
9. **Some wallet commands are dead on arrival.** Confidential shield/unshield/pay bail with "excised in the PQ migration" (`stell-wallet/src/main.rs:2479-2540`), yet remain in help/console.
10. **No public endpoint.** RPC and explorer bind loopback by default (`stellereum/src/node/bootstrap.rs:1260`, `:1288`); no TLS/reverse-proxy recipe or hosted instance is in tree.
11. **No contract upgrade path.** "Upgrade = redeploy" (`docs/site/03-contracts.md:55`); no proxy standard, no state-migration helper, no pause/upgrade ABI convention.
12. **No NFT/token standard beyond STS-20.** `rg -ni "nft|erc721|sts721" stellereum/src stellereum-contracts docs/site` finds only a color-hue comment (1 match); STS-20 exists (`stellereum-contracts/contracts/sts20-token/src/lib.rs:1-10`).

### 4.3 Minimal work to close

- Add thin aliases: `eth_getProof` → `stell_getProof` response shape, `eth_subscribe`/`eth_unsubscribe` → `stell_subscribe` hub, `eth_getBlockReceipts`. Owner: `stellereum/src/rpc/eth.rs`, `streams.rs`.
- Either make `net_peerCount`/fee fields live or return a JSON-RPC "unsupported" error; never serve a constant as if measured. Owner: `stellereum/src/rpc/eth.rs`, `stellereum/src/evm_adapter/`.
- Publish a JSON-RPC schema and generate TS/Python clients from it; add `openrpc.json` or an OpenAPI doc. Owner: `stellereum/docs/RPC.md`, new `schema/`.
- Add a tiny `stell_version`/`stell_chainSpec` pair (see §2.3).
- Add a proxy/upgrade example contract and a `migrate` helper in the contract SDK. Owner: `stellereum-contracts/crates/stellereum-contract-sdk/`, `docs/site/03-contracts.md`.
- Remove dead wallet commands or gate them behind an explicit `--experimental` flag.

---

## 5. Consensus and liveness

### 5.1 What exists

- **Protocol.** Tendermint/HotStuff-inspired pipelined BFT with proposer selection, rounds, prevote/precommit, QCs, value locking and view change (`stellereum/src/consensus/mod.rs:1-18`). Quorum is `floor(2n/3)+1` (`stellereum/src/consensus/sortition.rs:5-30`).
- **Votes and QCs.** Individually Falcon-512-signed and verified on ingestion (`stellereum/src/consensus/mod.rs:10-14`); precommit QC is the finality certificate (`stellereum/src/consensus/engine.rs:1762`), attached to the block (`stellereum/src/sharding/block.rs:270-278`).
- **Safety persistence.** Locks and safety checkpoints are persisted and restored across restarts with a capped round (`stellereum/src/node/consensus_driver.rs:640-700`, `:2657-2665`).
- **Liveness recovery.** Nil convergence (`stellereum/src/consensus/engine.rs:1945-2050`), a bounded deadlock breaker (`stellereum/src/consensus/engine.rs:2182-2230`; `stellereum/src/node/consensus_driver.rs:3692-3695`), and round re-phasing with no peer ahead (`stellereum/src/node/consensus_driver.rs:3758`).
- **Slashing.** Double-vote equivocation (`EQUIVOCATION_SLASH_BPS = 500`, `stellereum/src/staking.rs:247`), proposal equivocation (`rg -n "SysCallReportProposalEquivocation" stellereum/src/svm.rs` → dispatch at `:1026`, `:2986`), downtime slash `10 bps` (`stellereum/src/staking.rs:257`), jail for 1,000 heights (`:315`), block-carried evidence (`stellereum/src/sharding/block.rs:355-384`; application at `stellereum/src/state_engine/apply.rs:3561-3690`).
- **Validator set.** Derived from the staking ledger: self-bond ≥ 1,000 STELL, power = self-bond + delegations, top 250 (`stellereum/src/staking.rs:59`, `:209`, `:2252-2267`).
- **Delegation and rewards.** Delegate/undelegate, a ledger-level redelegate that has no client path (§1.4), reward splitting minus commission (`stellereum/src/staking.rs:3568-3610`), 350M reward cap (`:235`).
- **Key rotation.** `SysCallRotateValidatorKey` (`stellereum/src/svm.rs:838-844`, dispatch `:2116`), wallet `rotate-key` (`stell-wallet/src/main.rs:267`).
- **Light client.** External verifier with out-of-band validator set, QC verification, proof verification, rotation support (`stellereum/src/light_client_cli.rs:1-40`, `stellereum/src/light_client.rs:1189-1560`).
- **Observer role.** `STELL_OBSERVER=1` suppresses self-add so a follower derives the same genesis (`stellereum/src/node/bootstrap.rs:392-415`).

### 5.2 What is missing

1. **Unbiasable randomness is not active.** Sortition is seeded by `BLAKE3(domain || prev_block_hash || height || round)` (`stellereum/src/consensus/sortition.rs:295-306`, `:415-418`, `:432`), so the proposer of height H influences the committee for H+1. The code itself calls this out as predictable (`:295`). Both replacements are off: XMSS beacon draw (`:464`) and CN-VRF v3 (`:552`).
2. **Validator lifecycle has three dead ends** (unjail, commission change, redelegation), as detailed in §1.4.
3. **Historical validator sets are an in-memory ring.** `validator_set_history` is capped at 1,024 entries (`stellereum/src/runtime/mod.rs:221`, `:550`) and is not persisted (`rg -n "validator_set_history" stellereum/src/storage.rs stellereum/src/node/bootstrap.rs` → 0); after restart, old heights fall back to the current set or the conservative boundary (`stellereum/src/runtime/consensus_step.rs:1795-1808`). Historical QC verification and old light-client rotations therefore degrade.
4. **QC size is linear in validator count.** The baseline QC is `666·k + ceil(k/8)` bytes of raw Falcon signatures (`stellereum/src/qc_aggregate.rs:1-16`). Compact gossip is active (`COMPACT_GOSSIP_ACTIVATION_HEIGHT = 0`) for proposals, and the compact µQC codec exists, but its node emit/admit call sites are still deferred, so finality still ships the full `Committed` envelope. At 250 validators this is ~166 KB per QC per height, a bandwidth and storage tax that mature chains avoid with aggregation or succinct proofs.
5. **No doppelganger protection and no sentry topology.** `rg -ni "doppelganger|sentry" stellereum/src stellereum/docs` → 0. Validator keys must sit on an Internet-reachable node; there is no documented sentry/proxy pattern for P2P.
6. **MEV protection is not operational end-to-end.** The live path seals at admission with a node-local key, which the module itself says "hides nothing from that process" (`stellereum/src/mev.rs:10-32`). The threshold epoch seal's node-side DKG refuses because the KEM registry/seed are not derivable (`stellereum/src/mev_epoch.rs:80-92`), and `mev_v4` is explicitly dead/parked (`stellereum/src/mev_v4.rs:40-57`).
7. **Cross-shard 2PC is live, but topology is still fixed.** `XPC_ACTIVATION_HEIGHT = 0` arms PREPARE/PREPARE-ACK/COMMIT for every new transfer (`stellereum/src/xshard2pc.rs:146`); the two-shard soak covers real processes. The remaining scalability gap is the fixed `{0,1}` pair and the unexercised live split/merge, not the value protocol.
8. **No finality gadget for external checkpoints.** Finality is per-height QC; there is no periodically finalized checkpoint with a justification chain (Ethereum Casper-style) for very light clients. The light client compensates with a genesis anchor and header chain (`stellereum/src/light_client.rs:1235-1330`), which is workable but means long header sync.
9. **Downtime attribution depends on the next block's `last_qc`.** Blocks persisted before that field existed decode as "no evidence" (`stellereum/src/sharding/block.rs:355-383`), so replaying pre-upgrade history cannot slash downtime. This is documented, but it means an upgrade boundary creates an evidence gap.
10. **Set churn is height-based, not epoch-based.** The set is re-derived at boundaries from the ledger (`stellereum/src/runtime/consensus_step.rs:1538-1545`), so stake can change the active set every block; mature chains usually bound churn to epochs to protect liveness.

### 5.3 Minimal work to close

- **P0:** Add `SysCallUnjail`, `SysCallAnnounceCommission`/`SysCallApplyCommission`, and `SysCallRedelegate`; expose them in RPC and wallet; add end-to-end tests. Owner: `stellereum/src/svm.rs`, `stellereum/src/staking.rs`, `stellereum/src/rpc/writes.rs`, `stell-wallet/src/main.rs`.
- **P1:** After audit, flip `CNVRF_V3_ACTIVATION_HEIGHT` (or the beacon draw) and add a live soak. Owner: `stellereum/src/consensus/sortition.rs`, `docs/CNVRF_V3_ROLLOUT.md`.
- **P1:** Persist the validator-set history (or a checkpoint every N heights) and serve `stell_getValidatorsAt(height)`. Owner: `stellereum/src/runtime/consensus_step.rs`, `stellereum/src/storage.rs`.
- **P1:** Turn on compact gossip after a compatibility window; add a QC-size metric. Owner: `stellereum/src/consensus_net.rs`, `stellereum/src/qc_aggregate.rs`.
- **P2:** Document and test a sentry architecture; add a `--no-p2p-vote`/sentry mode. Owner: `stellereum/src/node/`, `stellereum/docs/OPERATIONS.md`.

---

## 6. Economics

### 6.1 What exists

- **Hard cap.** `TOTAL_SUPPLY_CAP = 1_000_000_000 * 1_000_000_000` nano-STELL (= 1e9 STELL, `stellereum/src/tokenomics.rs:27`), enforced by an atomic reservation before any engine mint (`stellereum/src/state_engine/accounts.rs:1761-1790`), and folded into the state root when non-zero (`stellereum/src/state_engine/accounts.rs:882-900`; `stellereum/src/commitment.rs:2013-2040`).
- **Sub-caps.** Genesis vault 250M (`stellereum/src/tokenomics.rs:28`), staking rewards 350M (`stellereum/src/staking.rs:235`), bridge mint 100M cumulative (`stellereum/src/bridge.rs:46`), plus 500k STELL/hour withdraw and deposit windows (`stellereum/src/bridge.rs:35`, `:41`).
- **Live emission.** 0.317 STELL per block to the proposer (`stellereum/src/tokenomics.rs:38`, `:320-330`), minted into `REWARDS_POOL` and claimed by validators/delegators (`stellereum/src/staking.rs:3568-3610`).
- **Cap-exact schedule.** Implemented as a gated geometric curve with pinned constants (`stellereum/src/tokenomics.rs:54-64`, `:416-460`), but inactive (`:51`).
- **Fees.** Admission floor is governance-set (`SetMinGasLimit`, `stellereum/src/governance.rs:206`); the transaction pays its declared `gas_limit` on every block path (`stellereum/src/state_engine/apply.rs:1796-1808`, `:1892`). Priority is an explicit bid that must be covered by the declared fee (`stellereum/src/mempool.rs:1028-1046`), and the proposer receives the fees (`stellereum/tests/fee_market_tests.rs:1-10`).
- **Slashing destination.** Burned, not sent to a treasury: `total_burned` rises by the burned amount (`stellereum/src/staking.rs:2340-2473`).
- **Governance parameters.** 13 actions: min bond, equivocation slash bps, default commission, block reward, PMM buffer, governance quorum, signal, oracle publisher add/remove, oracle breaker reset, min gas limit, software upgrade, cancel upgrade (`stellereum/src/governance.rs:168-214`). Proposals run for 3 days and execute after a 7,200-height timelock (`stellereum/src/governance.rs:36`, `:60`), with the proposer's stake locked while open (`:535-539`).
- **Vesting.** `TeamVestingSchedule` and a claim gate exist (`stellereum/src/staking.rs:3772-3845`).

### 6.2 What is missing

1. **Genesis supply is outside the cap and the allocation.** Each validator is credited 100M STELL by direct account write (`stellereum/src/node/policy.rs:358`, `stellereum/src/runtime/lanes.rs:13-18`), and the faucet 1M (`stellereum/src/node/policy.rs:489`, `stellereum/src/node/bootstrap.rs:785`). There is no check that the sum is below 1B, and the mint counter starts at zero (`stellereum/src/tokenomics.rs:24-26`). With 11 validators the chain would start above its own cap.
2. **The allocation table is decorative.** `TokenAllocation` (`stellereum/src/tokenomics.rs:67-73`) is never used on the live path; there is no vault/liquidity/treasury/team account created at genesis.
3. **Team vesting cannot be installed.** `rg -n "register_team_vesting\(" stellereum/src` returns only the two definition sites (the register and unregister functions); no opcode or RPC calls either. The claim gate can only fire for a schedule that no live path can create.
4. **Fee model is fixed and overcharges.** No gas-used refund on the block path (`stellereum/src/state_engine/apply.rs:1801-1808`), no dynamic base fee, no burn. A user who declares a 10M gas limit pays 10M even for a transfer.
5. **No treasury.** There is no treasury account and no `GovAction` that spends one (`stellereum/src/governance.rs:168-214`). The `ecosystem_treasury` field is a number in a struct.
6. **Emission is flat, not cap-exact.** `EMISSIONCapEXACT_ACTIVATION_HEIGHT = u64::MAX` (`stellereum/src/tokenomics.rs:55`), so the "1B cap-exact" story is not the live schedule; the flat schedule exhausts at ~1.10B blocks (`stellereum/src/tokenomics.rs:338-350`).
7. **Commission cannot change**, so the validator/delegator split is frozen at bond time (see §1.4).
8. **No fee/MEV redistribution policy.** Fees and priority bids go entirely to the proposer; there is no burn, no treasury share, no delegator share.
9. **Bridge caps are global only.** No per-sender/per-destination limit (`stellereum/docs/audits/KNOWN_ISSUES.md:423-431`), and no rate-limit metric.
10. **Supply counter is committed conditionally.** It joins the digest only when non-zero (`stellereum/src/commitment.rs:2013-2040`). It is persisted in `StateSnapshotV2` (`stellereum/src/state_engine/types.rs:648-663`; capture at `stellereum/src/state_engine/accounts.rs:2132-2143`), so a modern snapshot preserves it; the residual is a pre-field snapshot, where a zero counter has no root-level signal until the next mint. The root does not independently attest "gross lifetime minted" at zero.

### 6.3 Minimal work to close

- **P0:** Add a genesis-supply assertion: `validators.len() * GENESIS_VALIDATOR_BALANCE + GENESIS_FAUCET_BALANCE <= TOTAL_SUPPLY_CAP`, or derive genesis balances from a signed allocation manifest whose hash is committed. Owner: `stellereum/src/node/policy.rs`, `stellereum/src/node/bootstrap.rs`, `stellereum/src/runtime/lanes.rs`.
- **P0:** Charge gas-used and refund the difference, or explicitly document and test a fixed-fee model. Add an EIP-1559-style base fee with a burn if the goal is Ethereum-class economics. Owner: `stellereum/src/state_engine/apply.rs`, `stellereum/src/mempool.rs`.
- **P1:** Add `SysCallVestingRegister` gated to a governance/treasury key, or delete the dead vesting path. Owner: `stellereum/src/svm.rs`, `stellereum/src/staking.rs`.
- **P1:** Add a treasury account and `GovAction::TreasurySpend` with a timelock; route a configured share of fees/slashes there. Owner: `stellereum/src/governance.rs`, `stellereum/src/state_engine/`.
- **P2:** Activate the cap-exact emission after a live emission audit. Owner: `stellereum/src/tokenomics.rs`.

---

## 7. Security and process

### 7.1 What exists

- **Fuzzing.** 7 `cargo-fuzz` targets (`block_decode`, `cert_envelope_decode`, `consensus_msg_decode`, `evm_raw_tx_decode`, `frame_decode`, `peer_msg_decode`, `transaction_decode`) plus a deterministic economics fuzz battery (`stellereum/fuzz/fuzz_targets/`, `stellereum/tests/fuzz_economics_ext.rs:1-20`).
- **Differential tests.** QC batch-vs-scalar (`stellereum/tests/qc_batch_verify_tests.rs:1`, `:302`), vote/proposal batch verification (`stellereum/tests/batch_verify_tests.rs:134`, `:299`), commitment assembly (`stellereum/tests/commitment_assembly_differential_tests.rs:1-10`), replay/chain-binding (`stellereum/tests/replay_enforcement_tests.rs:1-10`).
- **Pentest batteries.** 16 `pentest_*` files in the core crate, one in the indexer, one in contracts; the summary counts 206 attack functions across 13 batteries (`docs/PENTEST_SUMMARY.md:1-30`).
- **Threat model and known issues.** `stellereum/docs/audits/THREAT_MODEL.md`, `INVARIANTS.md`, `KNOWN_ISSUES.md` (41+ entries with severity, exploitability and status).
- **Secrets and key files.** Argon2id + XChaCha20-Poly1305, 0600/0700 enforcement, plaintext opt-out, fail-closed on encrypted-without-passphrase (`stellereum/src/node_keys.rs:1-20`); faucet key file 0600-checked and zeroized (`stellereum/src/node/bootstrap.rs:1088-1100`).
- **Chain-id binding and replay.** Transactions and votes bind `consensus_chain_id` (`stellereum/src/consensus/types.rs:87-143`, `:978-992`); blocks mix chain id into the hash (`stellereum/src/sharding/block.rs:812-824`); governance signed proposals consume nonces (`stellereum/src/governance.rs:578-590`); session keys have scoped budgets/expiry (`stellereum/src/zkml.rs:276-300`, `:584`; wallet commands at `stell-wallet/src/main.rs:751-810`).
- **DoS bounds.** 1 MiB RPC body (`stellereum/src/rpc/state.rs:12`), 24 MiB block wire cap and 2,048 proof units (`stellereum/src/mempool.rs:760-769`), 10,000 txs and 500M gas per block (`stellereum/src/runtime/mod.rs:215-239`), per-sender mempool quotas and joint affordability (`stellereum/src/mempool.rs:505-540`), subscription caps (`stellereum/src/rpc/streams.rs:21-30`), per-IP rate limit (`stellereum/src/explorer.rs:27-37`).
- **Fail-closed crypto.** Disabled schemes refuse at parse time (e.g. ML-DSA-44 is refused rather than weakly verified; `stellereum/docs/audits/KNOWN_ISSUES.md:37-56`).

### 7.2 What is missing

1. **No external human audit or live-network pentest.** The in-tree third-party-shaped review explicitly excluded dynamic fuzzing, external crypto audit and live pentest (`docs/audits/NEURAL_AUDIT_2026-11-04.md:5`).
2. **No real bug bounty.** `SECURITY.md` still has `[LEAD-SETS-EMAIL]` and placeholder bounty terms (`SECURITY.md:1-7`, `:35-40`).
3. **No CI-enforced fuzzing.** The nightly gate runs only `fuzz_economics_ext`, not `cargo fuzz` (`scripts/nightly_gate.sh:10`, `:38-39`); the 7 libFuzzer targets require a nightly toolchain and manual invocation.
4. **No property-based or model-based testing.** No `proptest`, `quickcheck`, `loom`, `kani` or TLA+ artefact (`rg -n "proptest|quickcheck|kani|loom" stellereum/Cargo.toml infnode/crates/infnode/Cargo.toml stellereum-sdk/Cargo.toml stell-wallet/Cargo.toml stellereum-indexer/Cargo.toml` → 0 hits). There are randomized unit tests, but no systematic state-machine model.
5. **No formal invariant checking of consensus safety.** `INVARIANTS.md` is prose; there is no executable invariant monitor or model.
6. **No secret manager integration.** Passphrases come from environment variables or a TTY prompt (`stellereum/src/node_keys.rs:29-70`); the only remote backend is a JSON-over-HTTP signer (`stellereum/src/remote_signer.rs:1-25`), not a Vault/KMS/Secrets Manager client.
7. **No HSM for the consensus key** (see §1.9).
8. **No container/VM hardening baseline.** The image never drops root (`rg -n "^USER" stellereum/Dockerfile` → 0; `stellereum/Dockerfile:28-48`), and there is no seccomp/AppArmor profile or read-only-rootfs recipe (`find . -iname '*seccomp*' -o -iname '*apparmor*'` → 0). The systemd units also run as root by design (`stellereum/scripts/systemd/stell-nodeA.service:15-17`).
9. **No incident-response drill.** Runbooks exist, but no tabletop exercise or chaos test against a live-like multi-region network. The deterministic 4-node harness is in-process (`stellereum/tests/consensus_liveness_harness.rs`); `scripts/local-cluster.sh` runs local processes on one host, not a multi-region topology.
10. **No dependency/SBOM policy.** No `cargo audit`, `cargo deny`, SBOM generation or license gate in the gate scripts (`rg -n "cargo audit|cargo deny|sbom" scripts justfile` → 0).

### 7.3 Minimal work to close

- **P0:** Commission an external audit of consensus, staking, bridge, governance and PQ crypto; publish the report. Owner: process, `docs/audits/`.
- **P0:** Replace `SECURITY.md` placeholders with a monitored address, PGP key and funded bounty; publish a disclosure SLA. Owner: `SECURITY.md`.
- **P0:** Add a hosted CI pipeline that runs the existing gate, `cargo fuzz` smoke targets, `cargo audit`/`cargo deny`, and the restore drill. Owner: `.github/workflows/` (new), `scripts/`.
- **P1:** Add a KMS/HSM backend for Falcon signing (or a threshold signer with an audited protocol). Owner: `stellereum/src/remote_signer.rs`, `stellereum/src/node_keys.rs`.
- **P1:** Add a secrets-manager loader (`STELL_KEY_PASSPHRASE_FILE` exists; add a Vault/KMS option). Owner: `stellereum/src/node_keys.rs`.
- **P2:** Add a TLA+/Alloy model or a `loom`-style interleaving test for the lock/finalize path. Owner: `docs/specs/`, `stellereum/tests/`.

---

## 8. Developer and product

### 8.1 What exists

- **Contract engine.** `wasmi` with fuel metering, deterministic mode, no float, 13 host imports, bounded storage keys/events/return data (`stellereum/src/contract.rs:1-10`, `:52`, `:360-430`); WAT is the canonical source and is recompiled for `stell_verifyContractSource` (`stellereum/src/contract_source.rs`).
- **Contract SDK.** `no_std` Rust helper crate with storage, caller, value and host mocks (511 lines across `stellereum-contracts/crates/stellereum-contract-sdk/src/`).
- **ABI.** Typed manifest and encoder (`stellereum/src/contract_abi.rs`); codegen emits Rust and TypeScript stubs (`stellereum/src/bin/abi_codegen.rs:1-20`).
- **Examples.** Four contracts (STS-20 token, liquidity pool, STL DNS, account object) plus adversarial/econ regression suites (`stellereum-contracts/contracts/`).
- **Devnet and simulator.** Deterministic `devnet` and `sim`/`sim-replay` commands (`stellereum/src/cli/args.rs:62-105`), a 4-node in-process harness (`stellereum/tests/consensus_liveness_harness.rs`), and a local cluster script (`scripts/local-cluster.sh`).
- **Load testing.** A standalone load generator with safety checks (`scripts/loadtest/loadtest/src/`), benches for apply, packing, fees, PQ end-to-end and zkML (`stellereum/benches/`).
- **Docs.** ~10.4k lines under `docs/` (including this file and `docs/UPGRADE_AND_RECOVERY.md`) plus 2,986 lines of RPC docs and 2,348 lines of operations docs (`wc -l`), including a spec set `docs/specs/01-04` and phase-2 revisions.
- **Feature matrix and gate scripts.** `scripts/feature_matrix.sh`, `scripts/verify_testnet_ideal.sh`, `scripts/nightly_gate.sh`, `justfile`.

### 8.2 What is missing

1. **No hosted CI** (see §1.8).
2. **No Solidity/EVM contract path.** Contracts are WAT/WASM; the EVM adapter cannot execute bytecode (see §1.5).
3. **No contract upgrade/proxy standard** (`docs/site/03-contracts.md:55`).
4. **No package manager for on-chain contracts.** Deployment is a raw hex blob via RPC (`docs/site/03-contracts.md:20-30`); there is no version/dependency manifest, and source registration is single-contract only (`stell_registerContractSource`, `stellereum/src/rpc/contracts.rs:392-395`).
5. **No JS/TS/Python SDK, no React hooks, no wallet-adapter package.** The TypeScript output of `abi_codegen` is contract stubs only.
6. **No local one-command devnet with funded accounts and a faucet UI.** `devnet` is deterministic but headless; `local-cluster.sh` is a test stand, not a developer product.
7. **No public testnet endpoints, explorer, indexer or faucet.** Defaults are loopback (`stellereum/src/node/bootstrap.rs:1260`, `:1288`); faucet is opt-in (`:1081-1090`).
8. **Docs are strong but stale in places.** Examples: the state-engine comment still says the mint counter is "NOT YET IN THE STATE ROOT" (`stellereum/src/state_engine/mod.rs:300-305`) although the cached digest folds it (`stellereum/src/state_engine/accounts.rs:882-900`); `chain_spec` omits four activation gates (GOV_OPS, SPRT, RESHARE, UPGRADE_EXEC); `docs/site/03-contracts.md:32` still contains an unverified quickstart item.
9. **No OpenAPI/OpenRPC schema** (see §4.2).
10. **No user-facing examples for the hard parts.** The bridge adapters, oracle publisher and light-client verifier exist as libraries/tests, but there is no sample integration project for any of them, and the light-client usage example is the CLI itself (`stellereum/src/light_client_cli.rs:1-40`).
11. **No API versioning policy.** `NATIVE_API_VERSION = "1.0.0"` exists (`stellereum/src/native_api.rs:88`), but there is no deprecation policy or version negotiation for `stell_*`.

### 8.3 Minimal work to close

- **P0:** Hosted CI (see §7.3) plus a green-badge README.
- **P1:** Publish a TypeScript SDK (tx building, RPC, proofs, contract calls) generated from an OpenRPC schema; add a minimal React example.
- **P1:** Ship a `stell devnet` one-liner that boots 4 validators, funds 10 accounts, starts explorer/indexer/faucet, and prints URLs.
- **P1:** Add a proxy/upgrade example contract and a migration helper to the contract SDK.
- **P2:** Add a contract source registry UI and a package manifest format with lockfile.
- **P2:** Refresh the stale doc spots and add `chain_spec` coverage for all gates.

---

## 9. Cross-chain comparison

Severity: **Blocker** = cannot responsibly launch mainnet; **Major** = launch possible but product incomplete; **Minor** = polish; **Parity** = comparable to mature chains.

| Capability | Mature-chain norm (ETH / Solana / TON class) | Stellereum today | Severity |
|---|---|---|---|
| Protocol/state version in block | Fork version or feature set is observable and peers reject mismatches | No version in `Block` (`stellereum/src/sharding/block.rs:257-390`); only `COMMITMENT_VERSION` (`stellereum/src/commitment.rs:100`) and P2P `FRAME_VERSION` (`infnode/crates/infnode/src/proto.rs:135`) | **Blocker** |
| On-chain upgrade scheduling | Solana feature gates; TON config proposals; Ethereum social fork with fork-id | `SoftwareUpgrade` is proposed/voted/finalized by the active block path; execution is still gated by `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX` (`stellereum/src/governance.rs:80`) | Major |
| State migration on upgrade | Versioned migrations or documented client migrations | Legacy snapshot decoders only (`stellereum/src/storage.rs:2554-2640`); `COMMITMENT_VERSION` bump needs a wipe (`stellereum/src/commitment.rs:97-100`) | **Blocker** |
| Rollback | Coordinated binary rollback with state compatibility checks | Manual sequence documented (`stellereum/docs/OPERATIONS.md:1627-1650`); no automation | Major |
| Governance on multi-node | On-chain proposals/votes executed by blocks | Block path is active from genesis (`GOV_OPS_ACTIVATION_HEIGHT = 0`), all 13 actions execute deterministically; only `SoftwareUpgrade` execution is gated | Parity (upgrade exec still gated) |
| Treasury | On-chain treasury with spend proposals | No treasury account or spend action (`stellereum/src/governance.rs:168-214`); allocation is a struct field (`stellereum/src/tokenomics.rs:67-73`) | Major |
| Fee market | EIP-1559 base fee + burn (ETH), 50% fee burn (Solana), configurable fees (TON) | Fixed admission floor; block path charges declared `gas_limit`; no burn (`stellereum/src/state_engine/apply.rs:1796-1808`; `stellereum/src/mempool.rs:566-570`) | Major |
| Emission schedule | Cap-exact or explicitly governed issuance | Flat 0.317 STELL/block (`stellereum/src/tokenomics.rs:38`, `:320-330`); cap-exact gated off (`:51`) | Major |
| Supply cap | Enforced from genesis through all mint paths | Global mint counter is enforced and committed, but genesis premine bypasses it (`stellereum/src/runtime/lanes.rs:13-18`; `stellereum/src/node/policy.rs:358`) | **Blocker** |
| Slashing coverage | Double-sign, surround, downtime, light-client attacks | Double vote, double propose, downtime, block-carried evidence; no invalid-block/DA slashing (`stellereum/src/staking.rs:2340`, `:257`; `stellereum/src/state_engine/apply.rs:3561-3690`) | Parity for BFT; Minor gap |
| Validator lifecycle | bond/unbond/jail/unjail/commission/rotate | bond/unbond/delegate/undelegate/rotate exist; unjail, commission change and redelegate have no client path (`rg` counts in §1.4) | **Blocker** |
| Delegation | Delegation with commission market | Delegation and reward split exist; commission frozen at bond (`stellereum/src/staking.rs:3568-3610`; `:1529`, `:1599` with no callers) | Major |
| Unbiasable randomness | RANDAO/VDF/VRF | Parent-hash sortition (`stellereum/src/consensus/sortition.rs:295-306`); beacon/CN-VRF off (`:464`, `:552`) | Major |
| MEV protection | Encrypted mempool / threshold decryption / PBS | Order commitment enforced; threshold epoch seal not operational (`stellereum/src/mev.rs:10-32`; `stellereum/src/mev_epoch.rs:80-92`) | Major |
| Fork choice / finality | Heaviest-chain + finality gadget (ETH), Tower BFT (Solana), BFT (TON) | Tendermint-style per-height BFT with locks and precommit QC (`stellereum/src/consensus/mod.rs:1-18`; `stellereum/src/consensus/engine.rs:1762`) | Parity |
| Light client | Beacon sync / light client protocol / catch-up | External CLI with out-of-band validators, QC verification, account/storage proofs (`stellereum/src/light_client_cli.rs:1-40`; `stellereum/src/rpc/reads.rs:566-700`) | Parity |
| State proofs | `eth_getProof` for account + storage | `stell_getProof` supports storage keys (`stellereum/src/rpc/reads.rs:566-700`); no `eth_getProof` alias | Minor |
| Cross-shard | Async/sync cross-shard messaging, live split | 2PC active from genesis (`stellereum/src/xshard2pc.rs:146`), soak-covered; fixed pair; no live split (`stellereum/src/sharding/topology.rs:22-24`) | Major for scale |
| Bridge | Light-client or validator-set bridge with rate limits | Relayer 2/3 threshold (`stellereum/src/bridge.rs:13`, `:215-217`) plus SPV evidence (`stellereum/src/bridge_adapters.rs:1-40`); the header store is off-chain and "NOT consulted by consensus verify paths" (`stellereum/src/bridge_adapters.rs:258-265`); global caps only (`stellereum/src/bridge.rs:35`, `:41`, `:46`) | Major |
| EVM compatibility | Full EVM bytecode + tooling | No EVM interpreter; read views + PQ binding/carrier value transfers (empty calldata); contract creation/calls refused honestly (`stellereum/src/evm_adapter/binding.rs`) | Major gap for ETH ecosystem |
| RPC parity | Documented, versioned, OpenRPC/OpenAPI | 106 `stell_*` + 32 `eth_*`; no `eth_subscribe`, `eth_getProof`, `eth_accounts`, `eth_sendTransaction`; no schema | Major |
| Subscriptions | WS `eth_subscribe` + logs | `stell_subscribe` WS/SSE with 4 topics (`stellereum/src/rpc/streams.rs:48-70`, `:1652`); no `eth_subscribe` | Minor/Major |
| SDKs | JS/TS, Python, Go, Rust | Rust tx-builder only (`stellereum-sdk/src/lib.rs:1-20`); TS contract stubs via codegen | Major |
| Wallet | Browser, mobile, hardware, CLI | CLI only (`stell-wallet/src/main.rs`); no hardware wallet (`rg` → 0) | Major |
| Explorer/indexer | Hosted explorer + hosted indexer/API | In-tree explorer (12 routes) and SQLite indexer; loopback by default (`stellereum/src/explorer.rs:2204-2225`; `stellereum-indexer/src/server.rs:131-153`) | Major |
| Faucet/devnet | Public faucet + one-command devnet | Opt-in faucet with caps (`stellereum/src/rpc/faucet.rs:61-70`); deterministic devnet (`stellereum/src/cli/args.rs:62-105`) | Minor |
| Metrics/alerting | Hundreds of series, dashboards, Alertmanager | 38 series; 23 alert rules; no dashboards/Alertmanager (`ops/alert_rules.yaml:28`; `stellereum/scripts/monitor/alerts.rules:1-10`) | Major |
| Backups/pruning | Automated snapshots, restore drills, archival tiers | Archive default; prune mode; backup/drill scripts (`stellereum/src/storage.rs:238-284`; `scripts/backup_restore_drill.sh:1-20`) | Minor (manual) |
| Key custody | HSM/KMS for validator keys | Encrypted file keys; remote signer Ed25519-only; no Falcon HSM (`stellereum/src/remote_signer.rs:880`) | **Blocker** for institutions |
| External audit/bounty | Multiple audits, live bounty | AI static review only (`docs/audits/NEURAL_AUDIT_2026-11-04.md:5`); bounty placeholders (`SECURITY.md:1-7`) | **Blocker** |
| CI | Hosted CI on every PR | No `.github`; manual/nightly cron (`scripts/nightly_ci_notes.md:1-9`) | Major |
| Contract upgrade | Proxy standard / migration tooling | Redeploy to a new address only (`docs/site/03-contracts.md:55`) | Major |
| Oracle | Median/quorum with TWAP anchoring | Publisher set with 5% same-key drift and 10% breaker; no median/TWAP commit (`stellereum/src/oracle.rs:12-33`, `:26-27`) | Major |
| DoS bounds | Rate limits, mempool quotas, body caps | 1 MiB body, 30 req/s/IP, mempool quotas, 24 MiB block cap, 500M gas (`stellereum/src/rpc/state.rs:12`; `stellereum/src/mempool.rs:760-769`; `stellereum/src/runtime/mod.rs:215-239`) | Parity |
| Chain-id/replay | EIP-155, domain separation | Chain-bound tx/vote/block hashing; governance/session nonces (`stellereum/src/consensus/types.rs:87-143`; `stellereum/src/sharding/block.rs:812-824`) | Parity |

---

## 10. Prioritised roadmap

Effort: **S** ≤ 1 week, **M** 2–4 weeks, **L** 1–3 months, **XL** > 3 months (one experienced engineer; audit calendars excluded).

### P0 — must land before any mainnet claim

| # | Work | Effort | Owning file area |
|---|---|---|---|
| P0-1 | Activate block-carried governance on a testnet, then mainnet: flip `GOV_OPS_ACTIVATION_HEIGHT`, add propose/vote/execute to wallet+SDK, live soak with 4+ validators | M | `stellereum/src/state_engine/mod.rs`, `apply.rs`, `svm.rs`, `rpc/writes.rs`, `stell-wallet/src/main.rs` |
| P0-2 | Add `protocol_version` to `Block` + a fork-id in the P2P handshake; reject mismatched peers/proposals | M | `stellereum/src/sharding/block.rs`, `consensus/types.rs`, `infnode/crates/infnode/src/proto.rs` |
| P0-3 | Add `state_schema_version` + migration registry; refuse newer schemas; keep legacy decoders | L | `stellereum/src/storage.rs`, `node/bootstrap.rs` |
| P0-4 | Enable the upgrade-execution sweep; add expiry, structured `from/to_version`, queued plans (the late-halt predicate and marker guard already exist as of `f1b10b263`) | M | `stellereum/src/governance.rs`, `state_engine/apply.rs`, `node/consensus_driver.rs` |
| P0-5 | Add unjail / commission-change / redelegate opcodes + RPC + wallet + tests | M | `stellereum/src/svm.rs`, `staking.rs`, `rpc/writes.rs`, `stell-wallet/src/main.rs` |
| P0-6 | Reconcile genesis supply with the cap and allocation; add an assertion + manifest hash | M | `stellereum/src/node/policy.rs`, `node/bootstrap.rs`, `runtime/lanes.rs`, `tokenomics.rs` |
| P0-7 | Commission an external audit of consensus, staking, governance, bridge, PQ crypto; publish | L (calendar) | `docs/audits/`, process |
| P0-8 | Replace `SECURITY.md` placeholders; fund a bounty; publish disclosure SLA | S | `SECURITY.md` |
| P0-9 | Hosted CI: clippy, tests, fuzz smoke, `cargo audit`/`deny`, restore drill | S/M | new `.github/workflows/`, `scripts/` |
| P0-10 | Decide and enforce the EVM story: either ship a real EVM or make `eth_*` an honest, documented subset (no fake `net_peerCount`/`eth_getCode`) | M (honest subset) / XL (real EVM) | `stellereum/src/evm_adapter/`, `rpc/eth.rs`, `docs/RPC.md` |

### P1 — required for a credible platform

| # | Work | Effort | Owning file area |
|---|---|---|---|
| P1-1 | HSM/KMS or audited threshold signer for the Falcon vote key | L | `stellereum/src/remote_signer.rs`, `node_keys.rs` |
| P1-2 | Activate CN-VRF v3 (or XMSS beacon) after audit; live soak | M | `stellereum/src/consensus/sortition.rs`, `docs/CNVRF_V3_ROLLOUT.md` |
| P1-3 | Persist validator-set history; add `stell_getValidatorsAt(height)` | M | `runtime/consensus_step.rs`, `storage.rs`, `rpc/reads.rs` |
| P1-4 | Compact gossip / QC compression activation; QC-size metric | M | `consensus_net.rs`, `qc_aggregate.rs`, `metrics.rs` |
| P1-5 | Cross-shard 2PC activation + live split/merge soak; state transfer | L | `xshard2pc.rs`, `sharding/topology.rs`, `runtime/` |
| P1-6 | Public RPC/indexer/explorer/faucet with TLS, rate limits and abuse controls | M | `node/bootstrap.rs`, `explorer.rs`, `rpc/faucet.rs`, ops |
| P1-7 | TypeScript + Python SDK generated from an OpenRPC schema; one-command devnet | M | `stellereum-sdk/`, new `schema/`, `cli/args.rs` |
| P1-8 | Metrics expansion + dashboards + Alertmanager | S/M | `metrics.rs`, `ops/`, `stellereum/scripts/monitor/` |
| P1-9 | Fee model: gas-used refund + dynamic base fee/burn (or explicit fixed-fee spec) | L | `state_engine/apply.rs`, `mempool.rs`, `tokenomics.rs` |
| P1-10 | Treasury account + `TreasurySpend` governance action with timelock | M | `governance.rs`, `state_engine/` |
| P1-11 | Contract upgrade/proxy example + migration helper | M | `stellereum-contracts/`, `docs/site/03-contracts.md` |
| P1-12 | Proof surface: `eth_getProof`, contract-code proofs, historical proof pagination | S/M | `rpc/reads.rs`, `rpc/eth.rs`, `light_client.rs` |
| P1-13 | Bridge hardening: per-sender limits, watcher incentives, light-client adapter | XL | `bridge.rs`, `bridge_adapters.rs` |

### P2 — differentiation and polish

| # | Work | Effort | Owning file area |
|---|---|---|---|
| P2-1 | Threshold-KEM MEV sealing (replace classical Feldman/Ristretto layer) | XL | `mev_epoch.rs`, `mev_kem_registry.rs` |
| P2-2 | Oracle median/quorum + TWAP-anchored commits | M | `oracle.rs` |
| P2-3 | State rent / storage deposits (bounded state growth) | L | `state_engine/`, `storage.rs` |
| P2-4 | Formal model / executable invariants for lock/finality | L | `docs/specs/`, `tests/` |
| P2-5 | Sentry architecture + doppelganger protection | M | `node/`, `docs/OPERATIONS.md` |
| P2-6 | NFT / multi-token standard and SDK helpers | S/M | `stellereum-contracts/`, `token.rs` |
| P2-7 | Multi-region deployment (Helm/Terraform), log shipping, OTel traces | M | `ops/`, `scripts/systemd/`, `metrics.rs` |
| P2-8 | Refresh stale docs; include all activation gates in `chain_spec` | S | `docs/`, `chain_spec.rs`, `state_engine/mod.rs` |
| P2-9 | Deprecation/versioning policy for `stell_*` and native API | S | `rpc/`, `docs/RPC.md`, `native_api.rs` |

---

## 11. UNVERIFIED items and verification appendix

### 11.1 Post-analysis deltas from `f1b10b263`

The wave that was uncommitted when this analysis started was committed as `f1b10b263` at 00:58. It changes the following claims in this document; everything below is verified against the current tree:

- **Governance is active; binary execution is the remaining gate.** `GOV_OPS_ACTIVATION_HEIGHT = 0` and the deterministic sweep executes every non-upgrade action. `UPGRADE_EXEC_ACTIVATION_HEIGHT` (`stellereum/src/governance.rs:80`) is still `u64::MAX`, so a passed `SoftwareUpgrade` matures but does not install `upgrade_plan`.
- **The upgrade halt is a predicate.** `plan.height <= height` (`stellereum/src/node/consensus_driver.rs:3129`), the halt drains persistence before exit, and a durable marker plus startup guard refuses consensus until the upgraded binary proves the plan (`stellereum/src/node/upgrade_halt.rs:338-407`; `stellereum/src/node/bootstrap.rs:940-966`). Remaining gaps are expiry, `from/to_version` and queued plans.
- **The upgrade plan is committed.** `commitment.rs` hashes the plan's presence, name, height and digest (`stellereum/src/commitment.rs:784`), so a local-only plan can no longer hide behind an identical root.
- **`chain_spec` still lists 7 gates** (`stellereum/src/chain_spec.rs:130-180`): QC split, beacon, CN-VRF v3, compact gossip, emission, PQ transport, XPC. It still omits `GOV_OPS`, `UPGRADE_EXEC`, `MEV_RESHARE`, `SPRT_TIER3`, `CHAIN_BINDING` and `ZKML_CONTEXT_BINDING`.
- **Supply counter persistence.** The counter is folded into the digest (`stellereum/src/state_engine/accounts.rs:882-900`) and persisted in `StateSnapshotV2` (`stellereum/src/state_engine/types.rs:648-663`); genesis allocation remains pre-minted and uncounted (`stellereum/src/node/bootstrap.rs:775-788`).
- **Sharding 2PC is active from genesis.** `XPC_ACTIVATION_HEIGHT = 0` (`stellereum/src/xshard2pc.rs:146`); the target counts a proven COMMIT as one inbound credit and consumed mailbox records are pruned. The topology is still the fixed `{0,1}` pair with no live split.
- **Compact gossip is active for proposals; compact µQC is codec-only.** `COMPACT_GOSSIP_ACTIVATION_HEIGHT = 0` (`stellereum/src/consensus_net.rs:2097`); the proposal path is wired (sender/receiver/body server/loopback), while the µQC emit/admit call sites remain deferred. QC split is still off (`stellereum/src/consensus/sortition.rs:179`).
- **Contract caller authentication and a PMM concurrency fix landed.** These close two previously open defects but do not change the product gaps in §4 or §8.

### UNVERIFIED (cannot be settled from this tree; no live probe was performed)

1. **Current test/gate status.** Not run; a gate run was in progress. The 3,924 test attributes and green claims in older docs do not prove the current tree is green.
2. **Live network height, block time, TPS, validator count and stake distribution.** No live host was contacted.
3. **Whether a public testnet/mainnet endpoint, explorer, indexer or faucet currently exists.** In-tree defaults are loopback; publication is an operational act.
4. **Browser rendering of the explorer.** Routes and tests exist; no browser was driven.
5. **Live bridge adapters on TON/EVM/Solana.** Code and tests exist; no external chain was queried.
6. **Whether any external human audit exists outside the repository.** The tree contains only the AI static review.
7. **Whether a later wave changes any semantics cited here.** `f1b10b263` is accounted for in §11.1; refs are pinned to `be52ce87c` unless marked, so the symbol name is the stable anchor if the tree advances again.
8. **DV/CEX listing, market price, or token sale status.** Out of scope and not verifiable from code.

### Verification commands used (representative)

```sh
# baseline counts
find . -name '*.rs' -not -path '*/target/*' | wc -l
rg -c '^\s*#\[(tokio::)?test\]' stellereum/src stellereum/tests
rg -c 'pub const [A-Z0-9_]+: &str = "stell_' stellereum/src/metrics.rs
rg -n "ACTIVATION_HEIGHT: u64 = u64::MAX" stellereum/src
rg -n "unjail\(" stellereum/src
rg -n "announce_commission\(|apply_commission\(" stellereum/src
rg -n "fn redelegate\(" stellereum/src
rg -n "register_team_vesting\(" stellereum/src
rg -c "eth_subscribe|eth_unsubscribe" stellereum/src
rg -l "eth_accounts|eth_signTransaction|eth_sendTransaction|eth_getProof" stellereum/src
ls .github
```

### Exact zero-match results used above

- `rg -c "eth_subscribe|eth_unsubscribe" stellereum/src` → **0**.
- `rg -l "eth_accounts|eth_signTransaction|eth_sendTransaction|eth_getProof" stellereum/src` → **0 files**.
- `rg -n "GOV_OPS|SPRT|RESHARE|UPGRADE_EXEC" stellereum/src/chain_spec.rs` → **0**.
- `find . -iname '*alertmanager*'` → **0**.
- `rg -ni "pkcs11|hsm|yubikey" stellereum/src stell-wallet/src` → only HSM-gap comments, no integration.
- `ls .github` → no such directory.
- `rg -n "proptest|quickcheck|kani|loom" stellereum/Cargo.toml infnode/crates/infnode/Cargo.toml stellereum-sdk/Cargo.toml stell-wallet/Cargo.toml stellereum-indexer/Cargo.toml` → **0** matches.
- `find . -iname '*.tla'` → **0** files.

### What this document deliberately does not do

It does not re-list every known issue in `stellereum/docs/audits/KNOWN_ISSUES.md`; that file is the defect register. It does not claim the system is insecure; it claims specific capabilities are absent, inactive, or not reachable from a client. It does not treat test count as a proxy for correctness. After the mega-wave the two hard blockers are narrower: **binary upgrade execution is still gated** (`UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX`), and **there is no versioned upgrade/migration contract**. Governance itself is reachable and block-carried on a real N>1 network.
