# 00 — Project Map, Phase-2 (HDAE, code truth)

Phase-1 files (`00_PROJECT_MAP.md`, `01-04_*.md`, both dated 2026-10-29) remain
untouched: this worker is NEW-FILES-ONLY. Lead merges. Phase-2 files:

| Spec | File (this dir) | Truth source |
|---|---|---|
| Architecture | `01_ARCHITECTURE_OVERVIEW_PHASE2.md` | `stellereum/src/lib.rs`, `Cargo.toml`, module headers |
| Crypto/PQ | `02_CRYPTO_AND_PQ_PHASE2.md` | `post_quantum.rs`, `pq_registry.rs`, `bls.rs`, `vrf.rs`, `cn_vrf.rs` |
| VM/execution | `03_VM_AND_EXECUTION_PHASE2.md` | `svm.rs`, `evm_adapter.rs`, `state_engine.rs`, `runtime.rs`, `mempool.rs` |
| Net/consensus | `04_NETWORK_AND_CONSENSUS_PHASE2.md` | `consensus.rs`, `consensus_net.rs`, `network.rs`, `sync.rs` |

## Where truth lives (read these, not diaries)

- Protocol: `stellereum/PROTOCOL.md`; prior canonical audit (root)
  `COMPREHENSIVE_AUDIT_REPORT.md` (PART I byte-frozen per Phase-1 `01`).
- Classical registry: `docs/CLASSICAL_INVENTORY.md:1`.
- CN-VRF: `docs/PQ_CN_VRF_SPEC.md:1` (spec) + `stellereum/src/cn_vrf.rs:1-4` (sandbox).
- VRF activation plan: `docs/VRF_ACTIVATION_PLAN.md` (pointer only, UNVERIFIED content).
- Roadmaps/status: `docs/ROADMAP.md`, `STATUS.md` (machine-generated via
  `scripts/harness_status.sh`), `docs/TESTNET_READINESS_OPS.md`,
  `docs/LIVE_DEMOS_RUNBOOK.md`, `docs/PENTEST_NET_API.md`.

## Runbooks / gates (all paths verified to exist)

- `scripts/verify_testnet_ideal.sh`, `scripts/harness_status.sh`, `justfile`
  (gate loop per Phase-1 map; bodies not re-read this pass).
- Clippy/test/sim gate per `AGENTS.md` §4 (constitution injected from repo root).

## Claim accounting (Phase-2 set)

- ~140 cited claims across the 4 specs; ~11 marked UNVERIFIED inline:
  01: native-API count 22, infnode pure-PQ absence beyond inventory, `cn_vrf::`
  caller absence; 02: PQ-KEM absence beyond inventory, PoP-absence line,
  Schnorr-construction term, CN-VRF activation/sortition use; 03: host-fn name
  list, EIP-1559 mirror detail, apply interleave order, faucet/paymaster
  mechanics; 04: gap-0 const, stream-shed const, reputation mechanics.
- No commits/stashes/pushes performed (lead-only). No existing file modified.
  New files: the 5 in this report (this map + 4 specs), all under
  `docs/specs/` with `_PHASE2` suffix to avoid colliding with Phase-1 names.
