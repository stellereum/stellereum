# CONSISTENCY AUDIT — docs/brains/STATUS/FEATURES/scripts vs code reality

Date: 2026-11-01. Scope: READ-ONLY (no live ops, no builds/tests, no `clippy --fix`, no edits except this file).
Method: read every `docs/*.md` + `docs/**/*.md`, `STATUS.md`, `FEATURES.md`, `AGENTS.md`/`CLAUDE.md`/`.cursorrules`,
`scripts/*.md`, `scripts/agents/*.md`; spot-checked each claim with `rg` against code. Brains: absent
(no `brains/` dir found) — nothing to cross-check there.
Rule: `file:line ↔ file:line` pairs only; severity BLOCKER = wrong operational instruction,
HIGH = wrong protocol claim, LOW = stale number already covered elsewhere.

## BLOCKER (wrong operational instructions — do NOT follow until fixed)

1. Quickstart cites RPC/onboarding docs that do not exist under `docs/`
   - `docs/site/01-quickstart.md:6` (`docs/RPC.md`) ↔ `docs/site/01-quickstart.md:9` (`docs/VALIDATOR_ONBOARDING.md`)
     ↔ `docs/TESTNET_UX_COMPARISON.md:73` (already flags: "`docs/` listing has no `RPC.md`/`VALIDATOR_ONBOARDING.md`")
     ↔ `ls docs/*.md` (only `AUDIT_RED_CLOSURE/LIVE_DEMOS_RUNBOOK/PROPOSER_REWORK/REPLAY_ANALYSIS/ROADMAP/SIMULATOR/TESTNET_UX_COMPARISON/TEMPO_PROFILE/VRF_*`; canonical refs live at `stellereum/docs/RPC.md`, `stellereum/docs/VALIDATOR_ONBOARDING.md` per `docs/site/00-index.md:25-28`).
   - Same broken `docs/RPC.md` / `docs/OPERATIONS.md` / `VALIDATOR_ONBOARDING.md` refs repeat at
     `docs/site/02-concepts.md:9,17,54,95`, `docs/site/03-contracts.md:109`, `docs/site/04-validators.md:4,14,21,30,110`.
2. Operators runbook names scripts that do not exist
   - `docs/site/05-operators.md:5-6,24-26,37,68-69`
     (`scripts/join-network.sh`, `scripts/add-peer.sh`, `health_check.sh`, `stall_watchdog.sh`, `stell-node.sh`
     via `stall_watchdog.sh`, `join-network.sh`/`add-peer.sh` join flow)
     ↔ `ls scripts/` (only `agents/ cluster-nodes.conf cluster-watchdog.sh doctor.sh feature_matrix.sh harness_status.sh lib/ local-cluster.md local-cluster.sh node-prune-cron.sh README.md run-observer.sh stell-sync.sh systemd/ tools/ verify_testnet_ideal.sh`).
3. Operators runbook points at the wrong OPERATIONS.md path
   - `docs/site/05-operators.md:5,19,45,52-54` (`docs/OPERATIONS.md`, `rg … docs/OPERATIONS.md`)
     ↔ `ls docs/*.md` (no `OPERATIONS.md`) ↔ `stellereum/docs/OPERATIONS.md:52,1595` (canonical; `docs/site/00-index.md:27` agrees).
4. Quickstart RPC port contradicts the local-cluster reality
   - `docs/site/01-quickstart.md:12` (`RPC=http://127.0.0.1:8545`)
     ↔ `scripts/local-cluster.md:23-24` + `docs/LIVE_DEMOS_RUNBOOK.md:19-21` (RPC base is **not** 8545: taken by an ssh tunnel; per-node `18645+i`, `ss`-checked, fails loudly).
   - Following the quickstart against a local cluster connects to the tunnel, not the node.
5. Documented funding/send path is inoperative under the cluster's own PQ policy
   - `docs/LIVE_DEMOS_RUNBOOK.md:118-135` (§0.4: sign with faucet seed `1111…1` → `wallet send … --rpc …`)
     + `docs/site/01-quickstart.md:98-101` (`wallet send --from-key …`)
     ↔ `scripts/local-cluster.md:33-38` (`STELL_PURE_PQ=1` everywhere)
     ↔ `stellereum/src/sharding.rs:3472-3475` (`verify_signature` refuses legacy ed25519 under pure-PQ)
     ↔ `docs/LIVE_DEMOS_RUNBOOK.md:742-771` (measured 2026-11-01: `wallet send` → `invalid transaction signature`, same- and cross-shard; §0.4 path labelled UNVERIFIED/inoperative under PURE_PQ).
   - The same file's §"Unblocked 2026-11-01 — `wallet send-pq`" (`docs/LIVE_DEMOS_RUNBOOK.md:335-397`) is the working path; §0.4/§2 sketch were never updated to point at it.
6. Same-file stale blocker: 2PC "BLOCKED — do not attempt" vs landed `up2` mode
   - `docs/LIVE_DEMOS_RUNBOOK.md:262-280` ("`local-cluster.sh` is single-shard ON PURPOSE … Do not hack env files"; Appendix `docs/LIVE_DEMOS_RUNBOOK.md:506-512` still "blocked — local proof only")
     ↔ `docs/LIVE_DEMOS_RUNBOOK.md:687-741` (`up2 3` EXECUTED PASS, both shards finalizing) ↔ `scripts/local-cluster.md:14-15,77-121` (`up --shards 0,1` / `up2` documented).
   - Operator reading top-down stops at the stale prohibition and misses the landed mode below.

## HIGH (wrong protocol claims)

7. VRF activation "not wired" statement is stale — threading landed 2026-11-01
   - `docs/VRF_BLS_ACTIVATION.md:112-118` ("no `STELL_VRF_ACTIVATION_HEIGHT` read in `main.rs` … setting the env changes NO live consensus bytes") + `:244-247` ("`vrf_activation_from_env` is dead code … all four live call sites pass `Disabled + None`")
     ↔ `docs/VRF_ACTIVATION_PLAN.md:22-34` (rows 3–4: `main.rs:2734-2736` wrapper, `:3026-3051` carry+log, runtime seam `runtime.rs:1693-1740`)
     ↔ `docs/VRF_BLS_ACTIVATION.md:415-470` (§10: provisioning + registry loader + live verify/attribution threading LANDED, 7 new e2e tests)
     ↔ code: `stellereum/src/main.rs:2726-3114` (activation read, ARMED/inactive logs, `set_live_vrf_registry`), `stellereum/src/consensus.rs:2939-2940,3496-3497` (live verify sites consult env+registry), `stellereum/src/vrf.rs:87-155` + `:181-…` (`VRF_KEYS_ENV`, `vrf_registry_from_env`).
8. VRF observability "nothing exists" is stale
   - `docs/VRF_BLS_ACTIVATION.md:153-166` ("ONLY VRF log line is the stderr malformed warning; no activation banner/metric/RPC")
     ↔ `stellereum/src/main.rs:3080-3110` (`[vrf] VRF sortition ARMED from height H`, `inactive`, `VRF secret provisioned`, `registry empty/loaded` lines)
     ↔ `docs/VRF_ACTIVATION_PLAN.md:22-34` (row 3 logs).
9. Crypto spec phase-1 language is stale
   - `docs/specs/02_CRYPTO_AND_PQ.md:16` ("phase-1 wiring live … NOT audited ECVRF") + `:40-41` ("VRF math bound, NOT wired into sortition; BLS PoP format exists, gate unchanged")
     ↔ `docs/VRF_BLS_ACTIVATION.md:415-470` (§10 threading) ↔ `stellereum/src/consensus.rs:2939-2940,3496-3497`.
10. Consensus spec overstates the VRF election switch
    - `docs/specs/04_NETWORK_AND_CONSENSUS.md:10-11` ("at/after `H` with a verified proof, the seed IS the VRF election output")
      ↔ `docs/VRF_BLS_ACTIVATION.md:456-469` (verify/attribution threaded; `HeightConsensus` assembly sites still build legacy committees, seals flow via runtime seam only).
    - A reader expecting a full election switch gets verify-side fallback semantics instead.
11. Execution spec native-API count is wrong
    - `docs/specs/03_VM_AND_EXECUTION.md:22` ("22 pinned" native APIs)
      ↔ `stellereum/src/native_api.rs:627+` (35 `"stell_*" =>` dispatch arms counted by `rg -c`).
12. Gate-scope specs contradict each other and the scripts
    - `docs/specs/01_ARCHITECTURE_OVERVIEW.md:8` ("gates loop over all six")
      ↔ `docs/specs/00_PROJECT_MAP.md:42` ("7 ws") ↔ `scripts/verify_testnet_ideal.sh:20` + `scripts/harness_status.sh:7` (`RUST_WS="stellereum infnode stellereum-contracts stellereum-indexer stellereum-sdk stell-wallet scripts/tools/stelops"` = 7).
13. Feature-matrix / audit-gate status contradicts itself across footers
    - `docs/ROADMAP.md:40` (`[ ] Full feature-matrix re-run (39 rows + new suites)` unchecked) + `:85` ("audit-repro red: F4 2 tests … gate NOT green") + `:86` (KI-37…KI-41 open §M)
      ↔ `FEATURES.md:48` (`GREEN 39 / RED 0 / SKIP 0 — 39 rows`) ↔ `git log 6e4bbfa` ("matrix: refresh timings after full 39/39 green re-run")
      ↔ `docs/AUDIT_RED_CLOSURE.md:32-38` (F4/KI-37 CLOSED 2026-10-31: `audit_rpc_evm_closeout` 30/30, full repro `TOTAL 1845 passed / 0 failed`) + `:62-114` (KI-38 rewrite landed, PoCs green).
    - ROADMAP audit § (2026-10-30) is two days stale vs the closure report in the same `docs/` tree; a gate reader cannot tell green from red.

## LOW (stale numbers / wording, already covered elsewhere)

14. `STATUS.md:5` (`infmail-valid-backend`) vs rename — covered by `docs/ROADMAP.md:14,54` ("renamed to `infnode`") ↔ `scripts/harness_status.sh:7` (`infnode`) — regenerating STATUS fixes it.
15. `AGENTS.md:11` + `docs/specs/00_PROJECT_MAP.md:6` ("`stellereum_head/`/`w8/` stale copies, never touch") vs `docs/specs/01_ARCHITECTURE_OVERVIEW.md:23-24` (REMOVED 2026-10-29) ↔ `ls` (both absent) — warning is harmless but stale.
16. `AGENTS.md:10` cites `TASK_PROMPT_TEMPLATE.md` line 1 for scope lock; template is 17 lines, Phase 5 (`scripts/agents/TASK_PROMPT_TEMPLATE.md:1-3`) while AGENTS is Phase 6 — line drift only.
17. `docs/VRF_BLS_ACTIVATION.md:297-350` header ("35/35: 6+11+14+4") vs its own §10 battery (`:471-480`: +7+8+3+9+9+6+9+23+7+4+13+21 suites green) — header never updated after §9–§10 landed.
18. `STATUS.md:1` (generated 2026-10-29T15:12Z; archive "29 files") vs `docs/ROADMAP.md:81-86` + `docs/AUDIT_RED_CLOSURE.md:1` (2026-10-30/31 activity) — STATUS is machine-generated so staleness is by design, but footer readers treat it as current.
19. Snapshot cadence: `stellereum/docs/OPERATIONS.md:52` ("every 100 heights") + `stellereum/src/main.rs:5647,5659,5676` (100-height job) vs `stellereum/src/main.rs:264-266` (`STELL_SNAPSHOT_INTERVAL` default 1000) — already self-flagged as TODO at `docs/site/05-operators.md:52-54`; code default vs job cadence conflated.
20. `docs/site/00-index.md:29` ("36 known issues KI-01…KI-36") vs `stellereum/docs/audits/KNOWN_ISSUES.md:708-758` (KI-37…KI-41 §M) — index frozen at the audit-package cut (`docs/ROADMAP.md:84` `4d0d539`).

## Counts

- BLOCKER: 6 · HIGH: 7 · LOW: 7 · Total: 20.
- Brains: 0 findings (directory absent).

## Top-5 blockers (fix order)

1. Quickstart missing-file refs (#1) — every new dev hits dead `docs/RPC.md`/`VALIDATOR_ONBOARDING.md` links first.
2. Operators phantom scripts (#2) — join/health flow cannot be executed as written.
3. Wrong `docs/OPERATIONS.md` path (#3) — authority link 404s from repo root.
4. Quickstart `:8545` RPC (#4) — copy-paste commands target the ssh-tunnel port, not any cluster node.
5. Inoperative `wallet send` funding path under PURE_PQ (#5) — the only documented faucet-to-first-tx loop fails with `invalid transaction signature`; point §0.4/§2 at the `send-pq` path.
