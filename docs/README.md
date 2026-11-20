# Stellereum docs index

Curated map. One line per doc. Paths relative to the repo root unless noted.

## Protocol freeze (read first)

- `docs/PUBLIC_TESTNET_CODE_GAPS.md` — canonical freeze doc: single-shard default + fixed `{0,1}` pair, five decisions, removals, neural-audit gate (lead working doc, in Russian).
- `docs/RULESET_V6.md` — **current consensus ruleset**: `FORK_ID 0x0f584a46`, 23 rules, round-free lock identity + re-stamped rescue (v2–v5 pages are historical).
- `docs/RULESET_V5.md` — chain-wide supply cap (fork `0x9d59096b`; historical, superseded by v6).
- `docs/SUPPLY_CAP.md` — chain-wide `TOTAL_SUPPLY_CAP` model, `SupplyPartition`, failure modes.

## Specs

- `docs/specs/00_PROJECT_MAP.md` — where technical truth lives; start here.
- `docs/specs/01_ARCHITECTURE_OVERVIEW.md` — system architecture.
- `docs/specs/02_CRYPTO_AND_PQ.md` — Falcon-512 PQ, chain-id binding, classical inventory.
- `docs/specs/03_VM_AND_EXECUTION.md` — VM and execution rules.
- `docs/specs/04_NETWORK_AND_CONSENSUS.md` — BFT prevote/precommit, `floor(2W/3)+1` quorum.
- `stellereum/PROTOCOL.md` — consensus rules entry point (node dir).

## Audits & threat model

- `COMPREHENSIVE_AUDIT_REPORT.md` — root-level comprehensive audit report.
- `docs/audits/COMPREHENSIVE_AUDIT_REPORT.md` — docs-mirror of the audit report.
- `stellereum/docs/audits/THREAT_MODEL.md` — threat model; read before reporting.
- `stellereum/docs/audits/KNOWN_ISSUES.md` — known weaknesses incl. documented non-goals.
- `stellereum/docs/audits/INVARIANTS.md` — invariants a fix must hold.
- `stellereum/docs/audits/EXTERNAL_AUDIT_BRIEF.md` — external-audit brief (audit itself pending).
- `docs/PENTEST_SUMMARY.md` — pentest batteries summary.
- `docs/PENTEST_NET_API.md` — network/API pentest notes.

## Runbooks & operations

- `stellereum/docs/OPERATIONS.md` — operator guide (ports, keys, faucet fail-closed).
- `stellereum/docs/RPC.md` — JSON-RPC/WS surface.
- `stellereum/docs/SHARDING.md` — sharding: shard-1 parked, shards 2…16 design-only.
- `stellereum/docs/PERF_1K.md` — measured-only perf recipe; bench vs live labeled.
- `stellereum/docs/VALIDATOR_ONBOARDING.md` — how to validate on the testnet.
- `stellereum/testnet/README.md` — multi-node stand guide.
- `docs/TESTNET_READINESS_OPS.md` — testnet readiness checklist.
- `docs/LIVE_DEMOS_RUNBOOK.md` — live demo runbook.

## Crypto decisions

- `docs/PQ_CN_VRF_SPEC.md` — CN-VRF **v1 construction** (historical constants); v3 is implemented with the sortition gate off.
- `docs/CLASSICAL_INVENTORY.md` — historical (pre-wipe) 25-hole inventory; see its snapshot banner.
- `docs/CLASSICAL_REMOVAL_PHASE23.md` — classical-removal phases 2+3, design-only.
- `docs/WORKCHAIN_DECISION.md` — why single-shard is canonical.
- `docs/BFT_COMPARISON.md` — BFT comparison notes.

## Testing

- `FEATURES.md` — E2E matrix (machine-generated; 113 rows in the checked-in 2026-11-05 run: 42 green, 68 red, 3 skip — RED is a work order, not a pass).
- `docs/FUZZING.md` — 7 decode harnesses; corpus is git-ignored.
- `docs/SIMULATOR.md` — local simulator guide.

## Roadmap & status

- `docs/ROADMAP.md` — what-to-do list.
- `STATUS.md` — machine-generated gate status (do not hand-edit).
