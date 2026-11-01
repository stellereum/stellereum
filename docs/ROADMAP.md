# ROADMAP — what needs doing (HDAE canonical, curated, 2026-10-29)

Maintained by the lead only. Mark `[x]` with gate-output hash/date, never on intent.
Machine state: `STATUS.md`. Features: `FEATURES.md` (39 E2E rows). Why: `docs/specs/`.

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
- [ ] Full feature-matrix re-run (39 rows + new suites)
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
- [ ] VRF live path; BLS proof-of-possession (structural gaps, both pinned).

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
