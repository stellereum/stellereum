# ROADMAP — what needs doing (HDAE canonical, curated, 2026-10-29)

Maintained by the lead only. Mark `[x]` with gate-output hash/date, never on intent.
Machine state: `STATUS.md`. Why: `docs/specs/`.

## Done (verified)

- [x] clippy `-D warnings` 0/0 all 7 workspaces (2026-10-29)
- [x] Full suite green: 218 targets stellereum, infmail, e2e 7/7, wallet, indexer, sdk, stelops
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

- [ ] `cargo fmt` whole tree (advisory-dirty everywhere now) + flip fmt to hard gate.
- [ ] Install: `just`, `cargo-nextest`, `sccache`/`mold` (all absent; scripts degrade gracefully).
- [ ] System disk 86% (outside repo scope — operator level).

## Out of scope (org level, not agents)

- External security audit (mainnet/listing blocker), grants/accelerators, mainnet checklist.
