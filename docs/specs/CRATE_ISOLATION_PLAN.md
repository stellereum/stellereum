# CRATE_ISOLATION_PLAN (HDAE Phase 3, 2026-10-29, non-breaking)

## Current graph (from `cargo metadata --no-deps`)

- `stellereum` (single package, 60 src files) → path-dep `infnode`.
- `infnode`: `infnode` + `infmail` (infmail → infnode).
- `stellereum-contracts`: sdk + e2e + 4 contract crates.
- Standalone: indexer, sdk, wallet (lib+bin), stelops.
- NO root workspace. NO git repo (step zero: `git init` + first commit).

## Frozen core (touch = audit + spec update + full gate)

`address`/`cell`/`chain_binding` (formats), block/vote/QC wire types in
`sharding.rs`/`consensus.rs`, `state_engine.rs` apply(), mempool admission,
staking slash/bond math, PQ/signature domains.

## Copy discipline (immediate, zero-risk)

- `stellereum_head/` and `w8/` are stale diverged copies. Rule: no builds,
  no imports, no deploys from them. Deletion is deferred to a human decision
  (they may hold archaeology); the gate ignores them (no manifest in gate
  loop). Any agent found referencing them fails review.

## Non-breaking decoupling (staged, no file moves until git exists)

1. **Stage 0 (done):** gate loop covers all six workspaces; specs frozen.
2. **Stage 1:** forbid new cross-domain imports with a script
   (`scripts/check_import_graph.sh`): consensus/ files may not import from
   rpc/indexer/wallet-facing modules and vice versa (allowlist in script).
3. **Stage 2 (after git):** split order: `stell-primitives` (address, hashes,
   block types) → `stell-crypto` (PQ/BLS/VRF) → `stell-state` (trie, MMR) →
   keep node bin on top. Each split ships with byte-parity tests before the
   old path is removed.
4. **Never:** big-bang moves, renames of consensus-critical items, or
   signature changes without a compatibility shim + differential test.
