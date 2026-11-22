# Stellereum documentation index

This directory is the repository's **public technical documentation**. It is
the source of record for specs, runbooks, rulesets, RPC/operations material,
security posture and status. Every entry below is a file in this repository,
not a marketing page.

Three documentation sets are deliberately separate:

| Set | What it is | Where |
| --- | --- | --- |
| **Public docs (this index)** | Technical specs, runbooks, rulesets, operations, security and status. Durable, reviewable, linked from code and tests. | `docs/` and the in-tree files listed below |
| **Rendered portal** | The user-facing site at `https://docs.stellereum.org`. Built from `docs-site/`; presentation, navigation and quickstarts. | `docs-site/` (source), `scripts/deploy-docs-site.sh` (deploy) |
| **Internal archives** | Legacy agent notes, raw review/pentest working logs and removed internal diaries. Not public commitments and not maintained as documentation. | `.archive/`, git history; see `audits/INTERNAL_REVIEW_ARCHIVE.md` |

Where a document is a dated snapshot or historical ruleset, the entry says so.
Do not read a historical page as the current protocol.

## Status and roadmap

- [TESTNET_STATUS.md](TESTNET_STATUS.md) — honest public status: what is live, what is limited, operational constraints and roadmap summary.
- [ROADMAP.md](ROADMAP.md) — the lead-maintained what-to-do register, including the v7 rollout record and deferred work.
- [OPEN_DEFECTS.md](OPEN_DEFECTS.md) — defect register; currently 0 `OPEN` rows, with `FIXED`/`DEPLOYED`, `BY DESIGN` and `SEPARATE SYSTEM` states kept distinct.
- [../STATUS.md](../STATUS.md) — machine-generated clippy/fake-code gate status; do not hand-edit.
- [../FEATURES.md](../FEATURES.md) — generated E2E feature matrix (RED is a work order, not a pass).

## Specifications

- [specs/00_PROJECT_MAP.md](specs/00_PROJECT_MAP.md) — where technical truth lives; start here.
- [specs/01_ARCHITECTURE_OVERVIEW.md](specs/01_ARCHITECTURE_OVERVIEW.md) — system architecture and crate boundaries.
- [specs/02_CRYPTO_AND_PQ.md](specs/02_CRYPTO_AND_PQ.md) — Falcon-512, PQ1 envelopes, chain-id binding and the classical-excision position.
- [specs/03_VM_AND_EXECUTION.md](specs/03_VM_AND_EXECUTION.md) — VM, SVM, WASM and execution rules.
- [specs/04_NETWORK_AND_CONSENSUS.md](specs/04_NETWORK_AND_CONSENSUS.md) — BFT rounds, `floor(2·power/3)+1` quorum, finality and liveness rules.
- [../stellereum/PROTOCOL.md](../stellereum/PROTOCOL.md) — consensus rules entry point in the node crate.
- [specs/RULESET_V7_ACTIVATION_BLUEPRINT.md](specs/RULESET_V7_ACTIVATION_BLUEPRINT.md) — the v7 activation plan and gate inventory.
- [specs/05_LOCK_SAFETY_P0.md](specs/05_LOCK_SAFETY_P0.md) — lock/safety authority contract.
- [specs/06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md](specs/06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md) — bridge release-authorization design (not a live bridge).
- [specs/07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md](specs/07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md) — PQ validator lifecycle, rotation and withdrawal design.

## Rulesets and protocol economics

- [RULESET_V7.md](RULESET_V7.md) — **current ruleset**: `CONSENSUS_RULESET_VERSION = 7`, `FORK_ID 0x3ae00ebc`, all eight v7 gates active from genesis.
- [RULESET_V6.md](RULESET_V6.md) — previous ruleset (`0x0f584a46`); historical, superseded by v7.
- [RULESET_V5.md](RULESET_V5.md) — historical supply-cap fork; kept for protocol history.
- [SUPPLY_CAP.md](SUPPLY_CAP.md) — chain-wide `TOTAL_SUPPLY_CAP`, partitions and failure modes.
- [BFT_COMPARISON.md](BFT_COMPARISON.md) — BFT design comparison and measured liveness notes (read the dates).

## Runbooks

- [FRESH_GENESIS_RUNBOOK.md](FRESH_GENESIS_RUNBOOK.md) — deliberate new-chain procedure with preconditions and rollback limits.
- [TWO_SHARD_DEPLOY.md](TWO_SHARD_DEPLOY.md) — the supported fixed `{0,1}` deployment and 2PC rules.
- [LOADTEST_RUNBOOK.md](LOADTEST_RUNBOOK.md) — load-test safety model, funding math, measured baseline and stop conditions.
- [UPGRADE_AND_RECOVERY.md](UPGRADE_AND_RECOVERY.md) — upgrade halt/marker/exit-42 machinery, supervisor workflow, recovery and the no-rollback boundary.
- [UPGRADE_DRILL.md](UPGRADE_DRILL.md) — what the executable upgrade drills prove and what they do not.
- [LIVE_DEMOS_RUNBOOK.md](LIVE_DEMOS_RUNBOOK.md) — end-to-end demos for transfers, 2PC, contracts and related flows.
- [CI.md](CI.md) — CI/nightly jobs, curated suites, disk budget and historical scripts.
- [../scripts/README.md](../scripts/README.md) — every operations script with purpose, arguments, safety class and exact invocation.

## RPC, SDK and integration

- [../stellereum/docs/RPC.md](../stellereum/docs/RPC.md) — JSON-RPC/WS surface, confirmation semantics, gated methods and error shapes.
- [../stellereum/docs/WALLET_SIGNING.md](../stellereum/docs/WALLET_SIGNING.md) — wallet signing, chain binding and canonical messages.
- [SDK.md](SDK.md) — Rust/TypeScript SDK surface and parity notes.
- [../stellereum/docs/PAYMASTER.md](../stellereum/docs/PAYMASTER.md) — paymaster design and constraints.
- [../stellereum/docs/OBSERVABILITY.md](../stellereum/docs/OBSERVABILITY.md) — metrics, logs and health surfaces.

## Operations

- [../stellereum/docs/OPERATIONS.md](../stellereum/docs/OPERATIONS.md) — operator guide: ports, keys, faucet, systemd and incident procedure.
- [../stellereum/docs/VALIDATOR_ONBOARDING.md](../stellereum/docs/VALIDATOR_ONBOARDING.md) — validator onboarding and bond/registration flow.
- [../stellereum/docs/SHARDING.md](../stellereum/docs/SHARDING.md) — shard topology; shard 1 is parked, shards 2…16 are design-only.
- [../stellereum/docs/PERF_1K.md](../stellereum/docs/PERF_1K.md) — measured-only performance recipe; bench and live numbers are labelled.
- [../stellereum/docs/CONSENSUS_HOTPATH.md](../stellereum/docs/CONSENSUS_HOTPATH.md) — consensus hot-path structure and timing budget.
- [../stellereum-upgrader/README.md](../stellereum-upgrader/README.md) — coordinated upgrade supervisor: lifecycle, CLI, security rules and drill.
- [../stellereum-ledger-tool/README.md](../stellereum-ledger-tool/README.md) — offline block/segment verifier: exact commands, limits and safety rules.

## Security and audits

- [../SECURITY.md](../SECURITY.md) — disclosure policy, scope, threat-model pointers and testnet-only posture.
- [BRIDGE_THREAT_MODEL.md](BRIDGE_THREAT_MODEL.md) — bridge trust model, implemented vs **NOT IMPLEMENTED** paths, severity analysis.
- [audits/COMPREHENSIVE_AUDIT_REPORT.md](audits/COMPREHENSIVE_AUDIT_REPORT.md) — dated internal comprehensive audit report (Russian-language working evidence).
- [../stellereum/docs/audits/THREAT_MODEL.md](../stellereum/docs/audits/THREAT_MODEL.md) — node/network threat model; read before reporting.
- [../stellereum/docs/audits/KNOWN_ISSUES.md](../stellereum/docs/audits/KNOWN_ISSUES.md) — known weaknesses and documented non-goals.
- [../stellereum/docs/audits/INVARIANTS.md](../stellereum/docs/audits/INVARIANTS.md) — invariants a fix must hold.
- [../stellereum/docs/audits/EXTERNAL_AUDIT_BRIEF.md](../stellereum/docs/audits/EXTERNAL_AUDIT_BRIEF.md) — brief for an external audit; the audit itself has not been completed.

## Testing and verification

- [../FEATURES.md](../FEATURES.md) — E2E matrix; read RED/SKIP rows as work, not as passes.
- [FUZZING.md](FUZZING.md) — decode fuzz harnesses and corpus layout.
- [SIMULATOR.md](SIMULATOR.md) — local simulator and consensus harness usage.
- [CI.md](CI.md) — the PR gate and the authoritative nightly full gate.
- [CODE_INDEX.md](CODE_INDEX.md) — module/test index (generated from the tree; check dates).

## Design notes and dated analysis

- [WORKCHAIN_DECISION.md](WORKCHAIN_DECISION.md) — why the single-shard masterchain is canonical and why shard 1 is parked.
- [PQ_CN_VRF_SPEC.md](PQ_CN_VRF_SPEC.md) — CN-VRF specification; the v3 sortition gate remains off.
- [CLASSICAL_INVENTORY.md](CLASSICAL_INVENTORY.md) — historical classical-crypto inventory; see its snapshot banner.
- [LIGHT_CLIENT_VERIFY.md](LIGHT_CLIENT_VERIFY.md) — light-client verification design and limits.
- [COMPLETENESS_GAP_ANALYSIS.md](COMPLETENESS_GAP_ANALYSIS.md) — dated completeness review; useful evidence, not current status.
- [TESTNET_UX_COMPARISON.md](TESTNET_UX_COMPARISON.md) — dated UX comparison against other testnets.
- [WALLET_CONNECT_SPEC.md](WALLET_CONNECT_SPEC.md) — WalletConnect design; wallet/connect is deferred product work.
- [ZKML_AUDIT_AND_SEAM.md](ZKML_AUDIT_AND_SEAM.md) — zkML re-execution design and its non-ZK boundary.

## The docs.stellereum.org portal

The rendered documentation site is a **separate presentation layer**:

- [../docs-site/index.md](../docs-site/index.md) — VitePress home page and portal navigation source.
- [../docs-site/get-started/networks.md](../docs-site/get-started/networks.md) — portal network/endpoint/faucet page (source of the published URLs).
- [../docs-site/nodes/observer.md](../docs-site/nodes/observer.md) and [../docs-site/nodes/validator.md](../docs-site/nodes/validator.md) — portal onboarding pages.
- [../docs-site/security/status.md](../docs-site/security/status.md) — portal security-status page.
- Deploy tooling: [../scripts/deploy-docs-site.sh](../scripts/deploy-docs-site.sh). The deploy target is `https://docs.stellereum.org`.

The portal is the thing end users read. This `docs/` index is the thing an
operator, auditor or integrator reads when they need the file-level evidence
behind a portal statement. If wording differs, the repository file and the
current code/tests win for technical claims; the portal wins for presentation
and navigation.

## Internal archives

These are **not public documentation** and are not maintained as commitments:

- `../.archive/` — legacy agent notes and removed internal diaries.
- Git history — removed review/pentest working logs remain in history only.
- [audits/INTERNAL_REVIEW_ARCHIVE.md](audits/INTERNAL_REVIEW_ARCHIVE.md) — the public note explaining what was removed and where authoritative evidence now lives.

Raw `PENTEST_*`, `REVIEW_*`, `NEURAL_AUDIT_*` working notes are not part of the
public docs set. The durable evidence is `SECURITY.md`, `docs/audits/`,
`docs/OPEN_DEFECTS.md`, `docs/ROADMAP.md` and the test suite.
