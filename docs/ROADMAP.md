# ROADMAP — what needs doing (HDAE canonical, curated, 2026-10-29)

Maintained by the lead only. Mark `[x]` with gate-output hash/date, never on intent.
Machine state: `STATUS.md`. Features: `FEATURES.md` (38 E2E rows). Why: `docs/specs/`.

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

- [x] clippy `-D warnings` 0/0 all 7 workspaces (2026-10-29, holds after polish wave 1)
- [x] Full suite green: 218 targets stellereum, infmail, e2e 7/7, wallet, indexer, sdk, stelops
- [x] Polish wave 1 (5 agents, integrated 9d7ab9b, pushed `hdae-polish-*` to core+contracts):
  RPC 140-method drift pinned (7 new tests) · crypto gap pins: VRF-not-wired,
  BLS-refusal message, zkML-no-hiding (99 green) · contracts gate pins:
  workchain-bridge refusal, 2PC-off + AMM/u128 strengthened · consensus quorum
  value pins (4) + constant docs · state proof pins: archive-tamper at LC layer,
  snapshot roundtrip+garbage · lead: zkML spec section, Groth16 header fix
- [ ] Full feature-matrix re-run (38 rows; agents verified own rows green)
- [x] Session bloat archived (30 files), specs 00-04 + isolation plan written
- [x] Gate scripts + justfile + agents infra + AGENTS.md constitution
- [x] Prune timers on all 4 nodes, snapshot fresh, divergence-watch pattern
- [x] Stale-test repairs: wallet Falcon determinism pin, p3 halt-height race pin

## P0 — speed + repo bootstrap

- [ ] Deploy VEL fixes (prebuild + vote pipeline, in tree, harness 1744→635ms) to all 4 nodes, measure 45 min (target: mean ≤1.0s, p99 <2s, zero >5s). Twice aborted — needs a live window.
- [x] `git init` + baseline commit (833c71e); nested repos absorbed (history in `.archive/nested-history.txt`)
- [x] Per-part private remotes carry `hdae-baseline-2026-10-29` (main/agent branches untouched):
  `immtes/stellereum`, `immtes/infnode` (renamed from infmail-valid-backend),
  `immtes/stellereum-contracts`, `immtes/stell-wallet`, `immtes/stellereum-indexer`
- [ ] Hour-long block-time measurement (read-only) to settle sustained-tempo baseline.

## P1 — product gaps

- [ ] Workchain: execute PARK (S4 runbook) or fund + serve shard-1 RPC (currently wedged/empty).
- [ ] Live demos (code exists, never run live): split, 2PC finalize, DKG sealed round-trip.
- [ ] Legacy replay-protection rollout (envelopes).
- [ ] VRF live path; BLS proof-of-possession (structural gaps, both pinned).

## P2 — hygiene

- [x] `cargo fmt` whole tree (commit `fc028d9`, mechanical, checks green)
- [ ] Flip fmt to hard gate (currently advisory in `verify_testnet_ideal.sh`).
- [ ] Install: `just`, `cargo-nextest`, `sccache`/`mold` (all absent; scripts degrade gracefully).
- [ ] System disk 86% (outside repo scope — operator level).

## Out of scope (org level, not agents)

- External security audit (mainnet/listing blocker), grants/accelerators, mainnet checklist.
