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
- VRF activation plan: `docs/VRF_ACTIVATION_PLAN.md:1-8` (DRAFT plan, default-off;
  env `STELL_VRF_ACTIVATION_HEIGHT` per `stellereum/src/vrf.rs:87,132-150`;
  live call sites pin `Disabled`+`None`).
- Roadmaps/status: `docs/ROADMAP.md`, `STATUS.md` (machine-generated via
  `scripts/harness_status.sh`), `docs/TESTNET_READINESS_OPS.md`,
  `docs/LIVE_DEMOS_RUNBOOK.md`, `docs/PENTEST_NET_API.md`.

## Runbooks / gates (all paths verified to exist)

- `scripts/verify_testnet_ideal.sh`, `scripts/harness_status.sh`, `justfile`
  (gate loop per Phase-1 map; bodies not re-read this pass).
- Clippy/test/sim gate per `AGENTS.md` §4 (constitution injected from repo root).

## Claim accounting (Phase-2 set)

- ~140 cited claims across the 4 specs; 0 open verification items (all resolved
  with file:line citations in this pass):
  01: native-API catalog 35 (`native_api.rs:124-402`), infnode pure-PQ absence
  (`CLASSICAL_INVENTORY.md:30-34` + `pq_transport.rs:60-70`), `cn_vrf::`
  caller absence (zero callers by grep); 02: PQ-KEM op absence
  (`pq_transport.rs:60-70` + parked `mev_v4.rs:84-112`), PoP-absence line
  (`bls.rs:527-531`), Schnorr-construction term (`vrf.rs:106,113,145`),
  CN-VRF activation/sortition (`cn_vrf.rs:58`, `consensus.rs:1080-1086`);
  03: host-fn name list (`contract.rs:1193-1413`), EIP-1559 static-default
  detail (`evm_adapter.rs:115-123,328-368`), apply interleave order
  (`state_engine.rs:6437`), faucet/paymaster mechanics (`rpc.rs:274-275,599-607`,
  `sharding.rs:3892-3916`); 04: gap consts (`sync.rs:1640,1731`),
  stream-shed const (`consensus_net.rs:158`), reputation split
  (`network.rs:2112` + infnode `reputation.rs:1-27`).
- No commits/stashes/pushes performed (lead-only). No existing file modified.
  New files: the 5 in this report (this map + 4 specs), all under
  `docs/specs/` with `_PHASE2` suffix to avoid colliding with Phase-1 names.

## Addendum 8.5→9.0 (2026-11-02, append-only, no verified rewrites)

- 02 `02_CRYPTO_AND_PQ_PHASE2.md`: §7 CN-VRF API (`cn_vrf.rs:58-681`,
  `EPOCH_LEN`, zero `src/` callers); §8 `mev_pq_plan.rs` test-only
  (`lib.rs:31` `cfg(test)`, ranked R1/R2/R3 `:45-68`); §9 ml-kem crate
  (`infnode/.../Cargo.toml:36`, lock `0.3.4` `:1580-1582`) + KEM KATs
  (`kem_kat_tests.rs:144-238`, 1184/1088/768/1568 B) + UNWIRED proof
  (`pq_transport.rs:734-770`, stale `:60-70` noted); §10 privacy_pq/pq-gates
  harness (UNVERIFIED static: 0, runtime-only).
- 04 `04_NETWORK_AND_CONSENSUS_PHASE2.md`: §7 eclipse WIRED
  (`network.rs:3352,3358,3392,3585`, `eclipse_tests.rs:240-419`); §8 transport
  caps restated (no new consts).
- 03 `03_VM_AND_EXECUTION_PHASE2.md`: §6 fee-batching harness
  (`benches/fee_path.rs:168`, parity `fee_batching_parity_tests.rs:68-234`);
  §7 shard2 soak (`shard2_soak_tests.rs:83-293`, gate `main.rs:2723-2736`);
  §8 breaker bounds (`consensus.rs:3826`, `liveness_breaker_tests.rs:64-212`);
  §9 staking ops/checks (`staking.rs:59-3246`).
- 01 `01_ARCHITECTURE_OVERVIEW_PHASE2.md`: §5 light CLI
  (`main.rs:6751-6817`, `light_client_cli.rs:58-599`); §6 explorer/WS caps
  (`explorer.rs:29-966`, `rpc.rs:7333-7357`); §7 contracts audit
  (`COMPREHENSIVE_AUDIT_REPORT.md:1043-1221`, 35-row census + residuals).
- UNVERIFIED static count added this pass: 0 (bench ns/tx + soak walls are
  runtime-only by construction; harnesses cited, no measurements claimed).
