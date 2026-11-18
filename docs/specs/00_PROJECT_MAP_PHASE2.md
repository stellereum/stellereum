# 00 — Project Map, Phase-2 (HDAE, code truth)

Verified on the 2026-11-18 tree (base HEAD `0fdf1eefc` plus the day's in-flight
edits; line numbers match that tree), after the module split. This
map is the entry point for the Phase-2 set; it points at modules that exist on
the current tree. Any older pointer to `consensus.rs`, `runtime.rs`,
`state_engine.rs`, `rpc.rs`, `sharding.rs`, `evm_adapter.rs`, `bls.rs`,
`crypto_privacy.rs` or `docs/VRF_ACTIVATION_PLAN.md` is STALE — those files no
longer exist.

| Spec | File (this dir) | Truth source |
|---|---|---|
| Architecture | `01_ARCHITECTURE_OVERVIEW_PHASE2.md` | `stellereum/src/lib.rs`, `Cargo.toml`, module headers |
| Crypto/PQ | `02_CRYPTO_AND_PQ_PHASE2.md` | `post_quantum.rs`, `pq_registry.rs`, `cn_vrf.rs`, `minroot_vdf.rs`, `vrf.rs` (math only) |
| VM/execution | `03_VM_AND_EXECUTION_PHASE2.md` | `svm.rs`, `evm_adapter/`, `state_engine/`, `runtime/`, `mempool.rs` |
| Net/consensus | `04_NETWORK_AND_CONSENSUS_PHASE2.md` | `consensus/`, `consensus_net.rs`, `network.rs`, `sync.rs` |

## Where truth lives (read these, not diaries)

- Protocol: `stellereum/PROTOCOL.md`; audit findings:
  `docs/audits/COMPREHENSIVE_AUDIT_REPORT.md` and
  `docs/audits/NEURAL_AUDIT_2026-11-04.md`.
- Classical registry: `docs/CLASSICAL_INVENTORY.md:1`.
- CN-VRF: `docs/PQ_CN_VRF_SPEC.md:1` (spec) + `stellereum/src/cn_vrf.rs:1-4`.
- `docs/VRF_ACTIVATION_PLAN.md` and `STELL_VRF_ACTIVATION_HEIGHT` do **not**
  exist (ECVRF deleted; `vrf.rs` is lottery math only).
- Roadmaps/status: `docs/ROADMAP.md`, `STATUS.md` (machine-generated via
  `scripts/harness_status.sh`), `docs/TESTNET_READINESS_OPS.md`,
  `docs/LIVE_DEMOS_RUNBOOK.md`, `docs/PENTEST_NET_API.md`.

## Runbooks / gates

- `scripts/verify_testnet_ideal.sh`, `scripts/harness_status.sh`, `justfile`
  (gate loop per Phase-1 map).
- Clippy/test/sim gate per `AGENTS.md` §4 (constitution injected from repo root).

## Claim accounting (Phase-2 set, re-baselined 2026-11-18)

- The pre-split pass claimed ~140 cited claims and "0 open verification
  items". That accounting is **STALE**: the module split moved every line.
  This re-baseline keeps only claims that were re-grepped on the current tree,
  cites the module or exact line, and marks every stale section
  `STALE — see <module dir>`.
- 01: module map and crate table re-verified against `lib.rs`; native-API
  catalog is **32** methods (`native_api.rs:122-379`), not 35. 02: Falcon/ML-DSA
  sizes and CN-VRF API re-verified; BLS/ECVRF sections are deleted claims.
  03: VM caps, apply entry points and DeFi consts re-verified; function-level
  staking line lists are marked stale. 04: µQC rule, timeout ladder, sync and
  transport consts re-verified; the µQC rule now matches the code exactly
  (cap 128, network term 2/3).
- No commits/stashes/pushes performed (lead-only).
